"""Full tiny fact composition differential, separate from a production coverage signer."""
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "artifacts/mdd-026"

def require(ok, message):
    if not ok: raise RuntimeError(message)

def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

def canonical(rows):
    return collections.Counter(json.dumps(row, sort_keys=True, separators=(",",":"), ensure_ascii=True, allow_nan=False) for row in rows)

def exact(actual, expected, label):
    require(actual == expected, label + " differs\n" + repr(actual)[:500] + "\n" + repr(expected)[:500])

def definitions(raw, oracle):
    classes, fields, methods, interfaces = [], [], [], []
    for ordinal in range(oracle.header[16]):
        cls = struct.unpack_from("<8I", raw, oracle.header[17] + ordinal * 32)
        owner, flags, parent, intfs, source, annotations, at, static = cls
        classes.append({"class_def_idx":ordinal,"class_idx":owner,"descriptor":oracle.types[owner],"access_flags":flags,
            "superclass_idx":None if parent == 0xffffffff else parent,"source_file_idx":None if source == 0xffffffff else source,
            "annotations_byte_offset":str(annotations) if annotations else None})
        if intfs:
            count = struct.unpack_from("<I", raw, intfs)[0]
            for position in range(count):
                target = struct.unpack_from("<H", raw, intfs + 4 + position * 2)[0]
                interfaces.append({"class_def_idx":ordinal,"class_idx":owner,"ordinal":position,"interface_type_idx":target,"interface_descriptor":oracle.types[target]})
        if not at: continue
        counts = []
        for _ in range(4): n, at = oracle.uleb(at); counts.append(n)
        for group, count in enumerate(counts):
            index = 0
            for position in range(count):
                delta, at = oracle.uleb(at); access, at = oracle.uleb(at); index += delta
                row = {"class_def_idx":ordinal,"class_idx":owner,"ordinal":position,"access_flags":access}
                if group < 2:
                    row.update(field_idx=index,kind="static" if group == 0 else "instance"); fields.append(row)
                else:
                    offset, at = oracle.uleb(at)
                    body = {"state":"abstract"} if access & 0x400 else {"state":"native"} if access & 0x100 else {
                        "state":"present","code_byte_offset":str(offset),"declared_insns_size":struct.unpack_from("<I",raw,offset+12)[0]}
                    row.update(method_idx=index,kind="direct" if group == 2 else "virtual",body=body); methods.append(row)
    return classes, fields, methods, interfaces

def selected(records, keys):
    return [{k: row[k] for k in keys} for row in records]

def schema_rows(rows, schema, label):
    for row in rows:
        exact(set(row),{c["name"] for c in schema},label+" complete columns")
        for column in schema:
            value=row[column["name"]]
            if value is None:
                require(column["nullable"],label+":"+column["name"]+" unexpected NULL"); continue
            typ=column["data_type"]
            if typ.startswith("Utf8"): require(isinstance(value,str),label+" text type")
            elif typ=="UInt32": require(type(value) is int and 0<=value<=0xffffffff,label+" UInt32")
            elif typ=="Int64":
                require(isinstance(value,str) and str(int(value))==value and -(1<<63)<=int(value)<(1<<63),label+" exact decimal Int64")
            elif typ=="Float64":
                require(type(value) in [float,int] or value in ["NaN","Infinity","-Infinity"],label+" declared Float64 transport representation")
            else: raise RuntimeError("unhandled tested relation type "+typ)

def main():
    ref = load("tests/fixtures/references/oracle.py", "independent_reference_oracle_026")
    ann = load("tests/fixtures/annotations/oracle.py", "independent_annotation_oracle_026")
    inputs = json.loads((OUT / "probe-inputs.json").read_text(encoding="utf-8"))["cases"]
    relations = json.loads((ROOT / "conformance/manifests/relations.json").read_text(encoding="utf-8"))
    schemas = {row["name"]:row["columns"] for row in relations["relations"] if row.get("required_by_hostlab")}
    comparisons = []; retained = []; checks = 0
    for case in inputs:
        result = json.loads((ROOT / case["native_record"]).read_text(encoding="utf-8"))
        case_checks = 0
        for identity, native in zip(case["inputs"], result["dex_occurrences"]):
            raw = (ROOT / identity["path"]).read_bytes(); exact(hashlib.sha256(raw).hexdigest(), identity["sha256"], "source identity")
            oracle = ref.Oracle(raw); independent = oracle.read()
            metadata = native["metadata"]; source = native["source"]
            exact(metadata["source"], source, "metadata source binding")
            exact(native["code"]["source"], source, "code source binding")
            exact(native["raw_code_evidence"]["source"], source, "raw source binding")
            exact([s["data"]["text"]["utf16_units"] for s in metadata["strings"]], oracle.units, "lossless ordered UTF16 strings")
            exact([bytes(s["data"]["text"]["raw_mutf8"]).hex() for s in metadata["strings"]], oracle.raw_strings, "raw MUTF8 strings")
            exact([t["data"]["descriptor"] for t in metadata["types"]], oracle.types, "ordered type descriptors")
            exact([p["data"]["descriptor"] for p in metadata["prototypes"]], ["("+"".join(args)+")"+ret for ret,args in oracle.protos], "ordered proto params")
            defs = native["definitions"]
            exact([m["descriptor"] for m in defs["method_references"]], [oracle.method_descriptor(i) for i in range(len(oracle.methods))], "method references")
            exact([m["parameter_descriptors"] for m in defs["method_references"]], [m[3] for m in oracle.methods], "native ordered method parameter atoms")
            exact([f["descriptor"] for f in defs["field_references"]], [owner+"->"+name+":"+typ for owner,name,typ in oracle.fields], "field references")
            classes, fields, methods, interfaces = definitions(raw, oracle)
            for name, expected in [("classes",classes),("field_definitions",fields),("method_definitions",methods),("interfaces",interfaces)]:
                if expected: exact(selected(defs[name],list(expected[0])),expected,"ordered "+name)
                else: exact(defs[name],[],"empty "+name)
            actual_code = {int(row["data"]["raw_range"]["byte_offset"]):row["data"] for row in native["code"]["items"]}
            exact(set(actual_code),set(oracle.code),"all physical code item starts")
            for offset, code in actual_code.items():
                registers, ins, outs, tries, debug, size = struct.unpack_from("<HHHHII",raw,offset)
                exact([code["registers_size"],code["ins_size"],code["outs_size"],len(code["tries"]),code["insns_size_code_units"]],
                      [registers,ins,outs,tries,size],"code header")
                exact(code["insns_range"],{"byte_offset":str(offset+16),"byte_length":str(size*2)},"raw insns units")
                words=oracle.code[offset]["words"]; pc=0; opcodes=[]
                while pc<len(words):
                    opcode=words[pc]&255
                    width={14:1,0x1a:2,0x1b:3,0x1c:2,0x62:2,0x69:2,0x71:3,0x77:3,0xfa:4,0xfb:4,0xfc:3,0xfd:3,0xfe:2,0xff:2}.get(opcode)
                    require(width is not None and pc+width<=len(words),"independent tiny complete instruction subset")
                    opcodes.append([pc,opcode,width]); pc+=width
                exact([[i["code_unit_offset"],i["opcode"],i["width_code_units"]] for i in code["instructions"]],opcodes,"complete positional native opcode atoms")
            raw_records = native["raw_code_evidence"]["methods"]
            exact(len(raw_records),len(methods),"one raw record per defined method")
            for method, evidence in zip(methods,raw_records):
                exact(evidence["method"]["local_index"],method["method_idx"],"raw method identity")
                if method["body"]["state"] != "present":
                    exact([evidence["sha256"],evidence["insns_range"]],[None,None],"no body is not empty raw bytes")
                else:
                    at=int(method["body"]["code_byte_offset"])+16; length=method["body"]["declared_insns_size"]*2
                    exact(evidence["sha256"],hashlib.sha256(raw[at:at+length]).hexdigest(),"raw body fingerprint")
            references = native["references"]
            actual_sites = [{"caller_method_idx":s["caller_method_idx"],"class_def_idx":s["class_def_idx"],"class_idx":s["class_idx"],
                "pc":s["code_unit_pc"],"operand_ordinal":s["operand_ordinal"],"kind":s["target_kind"],"index":s["target_local_index"],
                "byte_offset":int(s["operand_range"]["byte_offset"]),"byte_length":int(s["operand_range"]["byte_length"]),"opcode":s["opcode"]} for s in references["sites"]]
            exact(actual_sites,independent["sites"],"ordered positional reference operands")
            for relation, expected in independent["relations"].items():
                if relation == "method_strings":
                    projection = references[relation]
                    if not independent["plain_scalar_string_projection"]:
                        exact(projection["error"]["code"],"UNSUPPORTED_QUERY","non-scalar projection guard")
                        retained.append({"case":case["case"],"relation":relation,"status":"lossless_raw_complete_plain_utf8_unavailable"}); continue
                    actual = projection["rows"]
                else: actual = references[relation]
                exact(canonical(actual),canonical(expected),"full reference relation "+relation)
                schema_rows(actual,schemas[relation],relation)
                exact(set(actual[0]) if actual else {x["name"] for x in schemas[relation]}, {x["name"] for x in schemas[relation]}, "full column set")
                comparisons.append({"case":case["case"],"relation":relation,"rows":len(actual),"complete_multiset_equal":True})
            if case["case"] in ["annotations","parameter-positions-unknown"]:
                expected_ann = ann.Oracle(raw).read(); actual_ann = native["annotations"]
                exact(actual_ann["source"],source,"annotation source binding")
                for relation, actual in actual_ann["rows"].items():
                    exact(canonical(actual),canonical(expected_ann[relation]),"complete annotation relation "+relation)
                    schema_rows(actual,schemas[relation],relation)
                    comparisons.append({"case":case["case"],"relation":relation,"rows":len(actual),"complete_multiset_equal":True})
                if case["case"] == "parameter-positions-unknown":
                    exact(actual_ann["prototype_positions_gate"]["code"],"INCOMPLETE_FACTS","prototype position absence not proven")
                    retained.append({"case":case["case"],"status":"encoded_annotation_rows_complete_prototype_positions_unknown"})
            if case["case"] == "annotations-bad-independent-scope":
                exact(native["annotations"]["operation_status"],"error","bad annotations not empty success")
                exact(native["annotations"]["error"]["code"],"INVALID_INPUT","real bad annotation error")
                exact(references["coverage"]["facts"],"complete","independent reference scope still complete")
                retained.append({"case":case["case"],"status":"required_annotation_layer_failure_must_block_whole_scope"})
            for column, error in native["method_column_gates"].items():
                exact(error["code"],"INCOMPLETE_FACTS","missing assembled methods projection "+column)
            case_checks += references["indexed_scalar_target_checks"]
        if case["case"] == "duplicate-occurrences":
            sources=[r["source"] for r in result["dex_occurrences"]]
            exact(sources[0]["content_id"],sources[1]["content_id"],"duplicate content identity")
            require(sources[0]["dex_occurrence_id"] != sources[1]["dex_occurrence_id"],"duplicate source occurrence collapsed")
            exact(len(result["foreign_occurrence_checks"]),1,"cross-source lookup rejection count")
        checks += case_checks
    report={"schema_version":"mdd.fact-composition-differential.v1","probe_cases":len(inputs),"dex_occurrences":sum(len(x["inputs"]) for x in inputs),
        "native_fact_composition_checks_passed":True,"indexed_scalar_target_checks":checks,"complete_relation_comparisons":comparisons,
        "retained_scope_boundaries":retained,"metadata_definitions_code_and_raw_fingerprints":"independent source-byte scalar oracle compared all tested occurrences",
        "production_coverage_signer_and_lazy_index_gate":"not_run; implementation delegated separately; this report never signs task completion",
        "native_method_atoms":{"ordered_parameters":True,"positioned_instruction_opcodes_and_count":True,"raw_bytes":True},
        "compatibility_relation_boundaries":["DefinitionFacts rejects code columns at its narrow layer boundary; validated CodeFacts supplies the native atoms", "native ordered parameter vector is exact; legacy UTF8 text serialization is a separate032 projection", "unassembled full Methods compatibility relation does not itself block native026 fact qualification"],
        "not_claimed":["all 17 production compatibility relation projections (separate032)","lazy/concurrent index lifecycle","production required_layers scope signer","full SQL/HostLab audit","private input","performance"]}
    (OUT/"facts-differential.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"probe_cases":len(inputs),"indexed_scalar_target_checks":checks,"complete_relation_comparisons":len(comparisons),"native_fact_composition_checks_passed":True,"task_026_complete":False}))

if __name__ == "__main__": main()
