#!/usr/bin/env python3
"""Independent scalar annotation oracle with explicit bounds and manual expectations."""
from __future__ import annotations

import hashlib
import json
import math
import struct
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
KIND = {0:"byte",2:"short",3:"char",4:"int",6:"long",0x10:"float",0x11:"double",0x15:"method_type",0x16:"method_handle",0x17:"string",0x18:"type",0x19:"field",0x1a:"method",0x1b:"enum",0x1c:"array",0x1d:"annotation",0x1e:"null",0x1f:"boolean"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Oracle:
    def __init__(self, data, max_depth=16, max_nodes=1000):
        self.data, self.max_depth, self.max_nodes, self.nodes = data, max_depth, max_nodes, 0
        self.version=data[4:7].decode("ascii")
        require(data[:8] == b"dex\n038\0" and len(data) >= 112, "header")
        require(struct.unpack_from("<I", data, 32)[0] == len(data), "file_size")
        require(hashlib.sha1(data[32:]).digest() == data[12:32], "signature")
        require(zlib.adler32(data[12:]) & 0xffffffff == struct.unpack_from("<I", data, 8)[0], "checksum")
        self.header = struct.unpack_from("<20I", data, 32)
        count = self.u32(self.header[5])
        self.sections = {}
        entries = [self.unpack("<HHII", self.header[5] + 4 + index * 12) for index in range(count)]
        for ordinal, (kind, unused, size, offset) in enumerate(entries):
            require(kind not in self.sections and unused == 0 and size > 0, "map")
            end = entries[ordinal+1][3] if ordinal + 1 < len(entries) else len(data)
            require(offset < end <= len(data), "map_bounds")
            self.sections[kind] = (offset, end, size)
        self.strings = []
        for index in range(self.header[6]):
            offset = self.u32(self.header[7] + 4 * index)
            length, after = self.uleb(offset, self.sections[0x2002][1])
            end = data.find(b"\0", after, self.sections[0x2002][1])
            require(end >= after, "string_terminator")
            text = data[after:end].decode("ascii")
            require(len(text) == length, "fixture_ascii_length")
            self.strings.append(text)
        self.types = [self.strings[self.u32(self.header[9] + index * 4)] for index in range(self.header[8])]
        self.fields = [self.unpack("<HHI", self.header[13] + index * 8) for index in range(self.header[12])]
        self.methods = [self.unpack("<HHI", self.header[15] + index * 8) for index in range(self.header[14])]
        self.protos = [self.unpack("<III", self.header[11] + index * 12) for index in range(self.header[10])]
        self.annotation_rows, self.element_rows, self.trees = [], [], {}

    def span(self, offset, size, end=None):
        require(0 <= offset <= len(self.data) and 0 <= size <= len(self.data)-offset, "truncated")
        require(end is None or offset + size <= end, "truncated")
        return self.data[offset:offset+size]

    def unpack(self, form, offset):
        return struct.unpack(form, self.span(offset, struct.calcsize(form)))

    def u32(self, offset):
        return self.unpack("<I", offset)[0]

    def uleb(self, offset, end):
        value = 0
        for ordinal in range(5):
            byte = self.span(offset + ordinal, 1, end)[0]
            value += (byte & 127) * 128**ordinal
            if byte < 128:
                require(value <= 0xffffffff, "uleb_overflow")
                return value, offset + ordinal + 1
        raise ValueError("uleb_overflow")

    def typed_annotation(self, offset, end, depth):
        type_index, at = self.uleb(offset, end)
        require(type_index < len(self.types) and self.types[type_index].startswith("L"), "annotation_type_out_of_range")
        count, at = self.uleb(at, end)
        require(count <= self.max_nodes, "node_budget")
        values, previous = [], -1
        for ordinal in range(count):
            name, at = self.uleb(at, end)
            require(name < len(self.strings) and name > previous, "annotation_element_order")
            node, at = self.value(at, end, depth, ordinal, name)
            values.append(node)
            previous = name
        return type_index, values, at

    def value(self, offset, end, depth, ordinal, name):
        require(depth <= self.max_depth, "depth_budget")
        self.nodes += 1
        require(self.nodes <= self.max_nodes, "node_budget")
        byte = self.span(offset, 1, end)[0]
        tag, arg = byte & 31, byte >> 5
        require(tag in KIND, "unknown_value_tag")
        require(tag not in [0x15,0x16] or self.version>="038","encoded_value_version")
        node = {"kind":KIND[tag], "depth":depth, "ordinal":ordinal, "name_idx":name, "offset":offset, "arg":arg}
        at = offset + 1
        if tag in [0x1c, 0x1d, 0x1e, 0x1f]:
            require(arg <= 1 if tag == 0x1f else arg == 0, "invalid_value_arg")
            if tag == 0x1c:
                count, at = self.uleb(at, end)
                require(count <= self.max_nodes, "node_budget")
                node["children"] = []
                for index in range(count):
                    child, at = self.value(at, end, depth+1, index, None)
                    node["children"].append(child)
            elif tag == 0x1d:
                inner_type, children, at = self.typed_annotation(at, end, depth+1)
                node.update(index=inner_type, children=children)
            elif tag == 0x1f:
                node["integer"] = str(arg)
        else:
            max_arg = {0:0,2:1,3:1,4:3,6:7,0x10:3,0x11:7}.get(tag, 3)
            require(arg <= max_arg, "invalid_value_arg")
            payload = self.span(at, arg+1, end)
            at += arg+1
            node["raw_payload_hex"] = payload.hex()
            if tag in [0,2,4,6]:
                node["integer"] = str(int.from_bytes(payload, "little", signed=True))
            elif tag == 3:
                node["integer"] = str(int.from_bytes(payload, "little"))
            elif tag in [0x10,0x11]:
                full_bytes = 4 if tag == 0x10 else 8
                bits = int.from_bytes(payload, "little") << (8*(full_bytes-len(payload)))
                node["bits"] = f"{bits:0{full_bytes*2}x}"
                value = struct.unpack("<f" if full_bytes == 4 else "<d", bits.to_bytes(full_bytes,"little"))[0]
                node["float_wire"] = "NaN" if math.isnan(value) else "Infinity" if value == math.inf else "-Infinity" if value == -math.inf else value
            else:
                target = int.from_bytes(payload, "little")
                limits = {0x15: self.header[10], 0x16: self.sections.get(8,(0,0,0))[2], 0x17:len(self.strings),0x18:len(self.types),0x19:len(self.fields),0x1a:len(self.methods),0x1b:len(self.fields)}
                require(target < limits[tag], "value_index_out_of_range")
                node["index"] = target
        node["end_offset"] = at
        return node, at

    def flatten(self, root_offset, node):
        self.element_rows.append({"file_id":0,"annotation_off":root_offset,"depth":node["depth"],"ordinal":node["ordinal"],"name_idx":node["name_idx"],
            "value_off":node["offset"],"value_end_off":node["end_offset"],"value_kind":node["kind"],"value_index":node.get("index"),"value_i64":node.get("integer"),"value_f64":node.get("float_wire")})
        for child in node.get("children",[]):
            self.flatten(root_offset, child)

    def read(self):
        encoded_arrays = {}
        if 0x2005 in self.sections:
            at, end, count = self.sections[0x2005]
            for _ in range(count):
                start = at
                size, at = self.uleb(at,end)
                require(size <= self.max_nodes,"node_budget")
                children=[]
                for ordinal in range(size):
                    child,at=self.value(at,end,0,ordinal,None)
                    children.append(child)
                encoded_arrays[start] = {"byte_offset":start,"end_offset":at,"children":children}
        if 7 in self.sections:
            start,_,count=self.sections[7]
            for ordinal in range(count):
                target=self.u32(start+ordinal*4)
                require(target in encoded_arrays,"call_site_array_not_item_start")
                children=encoded_arrays[target]["children"]
                require(len(children)>=3,"call_site_arity")
                require([child["kind"] for child in children[:3]]==["method_handle","string","method_type"],"call_site_prefix")
        start, end, count = self.sections[0x2004]
        at = start
        for _ in range(count):
            root = at
            visibility = self.span(at,1,end)[0]
            require(visibility in [0,1,2], "invalid_visibility")
            type_index, values, at = self.typed_annotation(at+1,end,0)
            self.trees[root] = {"type_idx":type_index,"visibility":visibility,"values":values}
            self.annotation_rows.append({"file_id":0,"annotation_off":root,"visibility":visibility,"type_idx":type_index,"element_count":len(values)})
            for value in values:
                self.flatten(root,value)
        require(0 <= end-at <= 3 and self.data[at:end] == b"\0"*(end-at), "annotation_items_trailing_bytes")
        sets, set_rows = {}, []
        at, end, count = self.sections[0x1003]
        for _ in range(count):
            start, size = at, self.u32(at)
            require(at+4+size*4 <= end, "annotation_set_bounds")
            targets = [self.u32(at+4+4*i) for i in range(size)]
            require(all(target in self.trees for target in targets), "annotation_target_offset")
            types = [self.trees[target]["type_idx"] for target in targets]
            require(types == sorted(set(types)), "annotation_set_type_order")
            sets[start] = targets
            set_rows.extend({"file_id":0,"annotation_set_off":start,"ordinal":i,"annotation_off":target} for i,target in enumerate(targets))
            at += 4+size*4
        ref_lists, ref_rows = {}, []
        at, end, count = self.sections[0x1002]
        for _ in range(count):
            start, size = at, self.u32(at)
            require(at+4+size*4 <= end,"parameter_ref_bounds")
            targets = [self.u32(at+4+4*i) for i in range(size)]
            require(all(target == 0 or target in sets for target in targets), "parameter_set_offset")
            ref_lists[start] = targets
            ref_rows.extend({"file_id":0,"annotation_set_ref_list_off":start,"ordinal":i,"annotation_set_off":target or None} for i,target in enumerate(targets))
            at += 4+size*4
        physical_directories = {}
        at,end,count=self.sections[0x2006]
        for _ in range(count):
            start=at
            class_set,fields,methods,parameters=self.unpack("<4I",at)
            require(at+16+8*(fields+methods+parameters)<=end,"directory_bounds")
            require(class_set == 0 or class_set in sets,"class_set_offset")
            at+=16
            inferred_owner=None
            local_entries=[]
            for kind,size in [("field",fields),("method",methods),("parameter",parameters)]:
                previous=-1
                for _ in range(size):
                    local,target=self.unpack("<II",at);at+=8
                    require(local>previous,"directory_entry_order")
                    pool=self.fields if kind=="field" else self.methods
                    require(local<len(pool),"directory_index")
                    owner=pool[local][0]
                    require(inferred_owner is None or owner==inferred_owner,"directory_owner_mismatch")
                    inferred_owner=owner
                    require(target in (ref_lists if kind=="parameter" else sets),"parameter_list_offset" if kind=="parameter" else "owner_set_offset")
                    local_entries.append((kind,local,target))
                    previous=local
            physical_directories[start]={"class_set":class_set,"fields":fields,"methods":methods,"parameters":parameters,"inferred_owner":inferred_owner,"entries":local_entries}
        directories, entries, owners = [], [], []
        for class_def_idx in range(self.header[16]):
            class_idx,_,_,_,_,directory,class_data,static_array = self.unpack("<8I",self.header[17]+32*class_def_idx)
            if static_array:
                require(static_array in encoded_arrays,"static_array_not_item_start")
                static_fields,_=self.uleb(class_data,len(self.data)) if class_data else (0,0)
                require(len(encoded_arrays[static_array]["children"])<=static_fields,"static_array_count")
            if directory == 0:
                continue
            require(directory in physical_directories,"directory_not_item_start")
            physical=physical_directories[directory]
            require(physical["inferred_owner"] is None or physical["inferred_owner"] == class_idx,"field_owner_mismatch")
            class_set,fields,methods,parameters=[physical[name] for name in ["class_set","fields","methods","parameters"]]
            directories.append({"file_id":0,"class_idx":class_idx,"annotations_off":directory,"class_annotations_off":class_set or None,"fields_size":fields,"methods_size":methods,"parameters_size":parameters})
            if class_set:
                require(class_set in sets,"class_set_offset")
                owners.append(("class",class_idx,class_set))
            for kind,local,target in physical["entries"]:
                if kind != "parameter":
                    owners.append((kind,local,target))
                entries.append({"file_id":0,"class_idx":class_idx,"annotations_off":directory,"entry_kind":kind,"entry_idx":local,
                    "annotation_set_off":target if kind != "parameter" else None,"annotation_set_ref_list_off":target if kind == "parameter" else None})
        signatures = {}
        for kind,local,target in owners:
            for annotation in sets[target]:
                tree = self.trees[annotation]
                if self.types[tree["type_idx"]] == "Ldalvik/annotation/Signature;":
                    require(len(tree["values"]) == 1 and tree["values"][0]["kind"] == "array","signature_shape")
                    fragments = tree["values"][0]["children"]
                    require(all(node["kind"] == "string" for node in fragments),"signature_fragment_type")
                    signatures["class" if kind == "class" else f"{kind}:{local}"] = "".join(self.strings[node["index"]] for node in fragments)
        return {"annotation_directories":directories,"annotation_directory_entries":entries,"annotation_set_entries":set_rows,"annotation_set_refs":ref_rows,
            "annotations":self.annotation_rows,"annotation_elements":self.element_rows,"signatures":signatures,"trees":self.trees,
            "physical_directories":physical_directories,"encoded_arrays":encoded_arrays}


def check_manual(oracle,result,expected):
    require(result["signatures"] == expected["signatures"],"manual_signatures")
    owner_labels = ["class"] + [("parameters" if row["entry_kind"] == "parameter" else row["entry_kind"]) + ":" + str(row["entry_idx"]) for row in result["annotation_directory_entries"]]
    require(owner_labels == expected["directory_owners"],"manual_directory_owners")
    arguments = oracle.protos[oracle.methods[0][1]][2]
    actual_types = [oracle.types[oracle.unpack("<H",arguments+4+2*index)[0]] for index in range(oracle.u32(arguments))]
    require(actual_types == expected["method_parameter_types"],"manual_parameter_type_order")
    empty_slots = [row["ordinal"] for row in result["annotation_set_refs"] if row["annotation_set_off"] is None]
    require(empty_slots == expected["empty_parameter_ordinals"],"manual_parameter_empty_slot")
    values_tree = next(tree for tree in oracle.trees.values() if oracle.types[tree["type_idx"]] == "Lfixture/Values;")
    actual = {oracle.strings[node["name_idx"]]:node for node in values_tree["values"]}
    require(set(actual) == set(expected["values"]),"manual_value_names")
    for name,value in expected["values"].items():
        node = actual[name]
        require(node["kind"] == value["kind"],"manual_kind:"+name)
        for key in ["integer","bits","index"]:
            if key in value:
                require(node[key] == value[key],"manual_value:"+name+":"+key)
        if "resolved" in value:
            pool = oracle.strings if node["kind"] == "string" else oracle.types
            require(pool[node["index"]] == value["resolved"],"manual_resolved:"+name)
        if "boolean" in value:
            require(node["integer"] == str(int(value["boolean"])),"manual_boolean:"+name)
        if name == "o_array":
            require([oracle.strings[child["index"]] for child in node["children"]] == value["string_values_in_order"],"manual_array_order")
        if name == "p_annotation":
            require(oracle.types[node["index"]] == value["type"] and node["children"][0]["integer"] == str(value["value"])
                and oracle.strings[node["children"][0]["name_idx"]] == "value","manual_nested_annotation")


def main():
    expected = json.loads((HERE/"expected.json").read_text())
    manifest = json.loads((HERE/"manifest.json").read_text())
    checks,positive = [],None
    for item in manifest["files"]:
        path = ROOT/item["path"]
        require(hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"],"fixture_identity")
        try:
            oracle = Oracle(path.read_bytes())
            result = oracle.read()
            require(item["expected"].startswith("valid_"),"unexpected_accept")
            if item["path"].endswith("/annotations-038.dex"):
                check_manual(oracle,result,expected)
                positive = result
            elif item["path"].endswith("/bad-parameter-arity.dex"):
                require(result["signatures"]==expected["signatures"] and len(result["annotation_set_refs"])==1,"parameter_prefix_semantics")
            elif item["path"].endswith("/valid-shared-empty-set.dex"):
                require(set(result["signatures"])=={"class","method:0"},"shared_empty_set_semantics")
            elif item["path"].endswith("/valid-shared-empty-directory.dex"):
                require(len(result["annotation_directories"])==2 and not result["annotation_directory_entries"] and not result["signatures"],"shared_empty_directory_semantics")
            else:
                require(result["signatures"]==expected["signatures"],"orphan_must_not_change_bound_signatures")
            checks.append({"path":item["path"],"status":"passed","outcome":"accepted bounded structural annotation scope"})
        except ValueError as error:
            accepted_reasons=[item["reason"]]
            if item["path"].endswith("/bad-class-owner.dex"):
                accepted_reasons.extend(["directory_owner_mismatch","directory_entry_order"])
            require(str(error) in accepted_reasons,"oracle_wrong_error:"+str(error)+" expected "+str(item["reason"]))
            checks.append({"path":item["path"],"status":"passed","outcome":str(error)})
    require(positive is not None,"missing_positive_fixture")
    budget = Oracle((HERE/"generated/annotations-038.dex").read_bytes(),max_depth=0)
    try:
        budget.read()
        raise ValueError("expected_depth_rejection")
    except ValueError as error:
        require(str(error) == "depth_budget","wrong_depth_budget_error")
    component_checks = []
    vectors = json.loads((HERE/"component-vectors.json").read_text())["vectors"]
    for vector in vectors:
        component = Oracle((HERE/"generated/annotations-038.dex").read_bytes(),max_depth=vector.get("max_depth",16),max_nodes=vector.get("max_nodes",1000))
        component.data = bytes.fromhex(vector["hex"])
        component.version = vector.get("version","038")
        try:
            node,end = component.value(0,len(component.data),0,0,None)
            require("reason" not in vector and end == len(component.data) and node["kind"] == vector["expected_kind"],"unexpected_component_accept")
            component_checks.append({"id":vector["id"],"status":"passed","kind":node["kind"]})
        except ValueError as error:
            require(str(error) == vector.get("reason"),"component_wrong_error:"+str(error))
            component_checks.append({"id":vector["id"],"status":"passed","rejection":str(error)})
    output = {"schema_version":"mdd.annotation-independent-oracle.v1","success":True,"fixture_checks":checks,"depth_budget_rejection":"passed",
        "positive":positive,"component_checks":component_checks,"independence":"Python scalar reference with handwritten expected.json; no Rust parser or fixture generator imports; Python struct/hashlib/zlib common primitives only",
        "qualification":"oracle/fixture preparation only, not MDD-022 production task completion"}
    (HERE/"oracle-results.json").write_text(json.dumps(output,indent=2,allow_nan=False)+"\n",encoding="utf-8")
    print(f"annotation oracle passed: {len(checks)} fixtures, {len(component_checks)} components, {len(positive['annotation_elements'])} flattened value rows, depth budget rejected")


if __name__ == "__main__":
    main()
