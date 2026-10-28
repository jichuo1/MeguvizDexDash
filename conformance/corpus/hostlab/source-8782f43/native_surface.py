"""Native metadata/call scan with original bytecode fingerprints and shared rules."""
import hashlib
import re
import zipfile

from native_graph import UnsupportedAudit
from native_session import literal, in_list
import surface_workers as W


def prefix(column, value):
    # Native LIKE is case-insensitive: use it only as an indexed superset filter.
    # The shared Python classifier below supplies the exact case-sensitive gate.
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return column+" LIKE "+literal(escaped+"%")+" ESCAPE '\\'"


def family_filter(column):
    prefixes = {p for values in W.FAMILIES.values() for p in values}
    prefixes.update({"Lcom/bilibili/app/comment3/ui/", "Lkntr/common/comment", "Lkntr/app/following/"})
    return "("+" OR ".join(prefix(column, p) for p in sorted(prefixes))+" OR ("+prefix(column, "Lcom/bilibili/bplus/")+" AND (lower("+column+") LIKE '%dynamic%' OR lower("+column+") LIKE '%following%' OR lower("+column+") LIKE '%feed%')))"


def protocol_filter(column):
    return "("+column+" IN ("+in_list(W.PROTOCOLS.values())+") OR "+column+" LIKE 'Lcom/bapis/%Moss;')"


def member(value):
    owner, tail = value.split("->", 1)
    name, proto = tail.split("(", 1)
    return owner, name, "("+proto


def legacy_body_order(proto):
    parameters, result = proto[1:].split(")", 1)
    tokens = re.findall(r"\[*(?:[ZBSCIJFD]|L[^;]+;)", parameters)
    if "".join(tokens) != parameters:
        raise UnsupportedAudit("method prototype cannot preserve the legacy bytecode fingerprint ordering")
    return "("+" ".join(tokens)+")"+result


def per_file(session, select, condition, order, *, group=None, **bounds):
    for file in session.files:
        sql = select+" WHERE file_id="+str(file)+" AND ("+condition+")"
        if group: sql += " GROUP BY "+group
        yield from session.rows(sql+" ORDER BY file_id,"+order, **bounds)


def code_locations(session, methods):
    result = {}
    for file, values in methods.items():
        if not values:
            continue
        lower, upper = min(values), max(values)
        # One constant-size predicate per DEX narrows transport without repeated
        # large IN-list evaluation. Preserve the original exact membership test.
        sql = ("SELECT method_idx,insns_off,insns_size FROM code_items WHERE file_id="+str(file)+
               " AND method_idx BETWEEN "+str(lower)+" AND "+str(upper)+" ORDER BY method_idx")
        for row in session.rows(sql, max_rows=200000):
            index = int(row["method_idx"])
            if not lower <= index <= upper:
                raise RuntimeError("native code location is outside the requested method range")
            if index in values:
                result[(file, index)] = int(row["insns_off"]), int(row["insns_size"])*2
    return result


def scan(session):
    names = sorted(session.files.values(), key=lambda n:int(re.sub(r"\D", "", n) or 1))
    if any("#" in n for n in names):
        raise UnsupportedAudit("DEX 041 container fingerprint equivalence is not admitted")
    numeric = [int(re.sub(r"\D", "", name) or 1) for name in names]
    if len(numeric) != len(set(numeric)):
        raise UnsupportedAudit("ambiguous numeric DEX ordering in fingerprint input")
    file_map = {file: names.index(name) for file, name in session.files.items()}
    records, methods, identities = {}, {}, {}
    for row in per_file(session, "SELECT file_id,class_def_idx,descriptor,superclass_descriptor FROM classes", family_filter("descriptor"), "class_def_idx"):
        group = W.family(row["descriptor"])
        if group is None:
            continue
        file, owner = int(row["file_id"]), row["descriptor"]
        key = file, owner
        if key in records:
            raise UnsupportedAudit("duplicate class definition in native surface scan")
        records[key] = {"file_id":file_map[file], "family":group, "class":owner,
            "superclass":row["superclass_descriptor"], "fields":[], "methods":[]}
    for row in per_file(session, "SELECT file_id,class_descriptor,field_name,field_descriptor FROM class_fields", family_filter("class_descriptor"), "class_idx,field_idx"):
        key = int(row["file_id"]), row["class_descriptor"]
        if key not in records: continue
        records[key]["fields"].append((row["field_name"], row["field_descriptor"].split(":", 1)[1]))
    for row in per_file(session, "SELECT file_id,class_descriptor,method_idx,method_name,method_descriptor FROM class_methods", family_filter("class_descriptor"), "class_idx,method_idx"):
        file, index, owner = int(row["file_id"]), int(row["method_idx"]), row["class_descriptor"]
        if (file, owner) not in records: continue
        _, name, proto = member(row["method_descriptor"])
        if (file, owner, name, proto) in identities:
            raise UnsupportedAudit("duplicate method definition in native surface scan")
        records[(file, owner)]["methods"].append((name, proto))
        methods.setdefault(file, {})[index] = (owner, name, proto)
        identities[(file, owner, name, proto)] = index
    code = code_locations(session, methods)
    with zipfile.ZipFile(session.apk) as archive:
        for file, values in methods.items():
            info = archive.getinfo(session.files[file])
            if info.file_size > 128*1024*1024:
                raise UnsupportedAudit("single DEX fingerprint input exceeds admitted memory budget")
            raw = archive.read(info)
            if raw[:4] != b"dex\n" or raw[4:7] not in {b"035", b"036", b"037", b"038", b"039", b"040"}:
                raise UnsupportedAudit("native raw-code fingerprint DEX version is not admitted")
            for (record_file, owner), record in records.items():
                if record_file != file: continue
                digest = hashlib.sha256()
                record["fields"].sort(); record["methods"].sort()
                for name, proto in sorted(record["methods"], key=lambda m:(m[0], legacy_body_order(m[1]))):
                    digest.update((name+proto).encode())
                    index = identities[(file, owner, name, proto)]
                    position = code.get((file, index))
                    if position is not None:
                        offset, size = position
                        if offset < 0 or offset+size > len(raw) or offset%2:
                            raise RuntimeError("native code interval is outside the verified DEX")
                        digest.update(raw[offset:offset+size])
                record["method_bodies_sha256"] = digest.hexdigest()
                record["compose_signatures"] = [name+proto for name, proto in record["methods"] if "Landroidx/compose/runtime/Composer;" in proto]
    edges, counts = set(), {}
    condition = family_filter("callee_class")+" OR "+protocol_filter("callee_class")
    for row in per_file(session, "SELECT file_id,method,callee,COUNT(*) AS n FROM method_calls", condition, "method,callee", group="file_id,method,callee", max_rows=1000000, max_bytes=256*1024*1024):
        file = int(row["file_id"])
        caller, name, proto = member(row["method"])
        callee, target_name, target_proto = member(row["callee"])
        group = next((key for key, value in W.PROTOCOLS.items() if value == callee), None)
        group = group or ("unregistered_protocol:"+callee if callee.startswith("Lcom/bapis/") and callee.endswith("Moss;") else W.family(callee))
        if group is None: continue
        source = W.family(caller) or "external_or_unknown"
        edges.add((file_map[file], source, caller, name, proto, group, callee, target_name, target_proto))
        counts[(file_map[file], source, group)] = counts.get((file_map[file], source, group), 0)+int(row["n"])
    definitions = []
    for row in per_file(session, "SELECT file_id,method_descriptor FROM class_methods", protocol_filter("class_descriptor"), "class_idx,method_idx"):
        owner, name, proto = member(row["method_descriptor"])
        if owner not in W.PROTOCOLS.values() and not (owner.startswith("Lcom/bapis/") and owner.endswith("Moss;")): continue
        group = next((key for key, value in W.PROTOCOLS.items() if value == owner), "unregistered_protocol:"+owner)
        definitions.append((file_map[int(row["file_id"])], group, name, proto))
    # The legacy report's ordering is per numeric DEX, then class definition order.
    parts = [{"rule_sha256":W.RULE_SHA256, "classes":[r for r in records.values() if r["file_id"] == file],
              "edges":sorted(e for e in edges if e[0] == file),
              "edge_counts":[(a, b, count) for (f, a, b), count in sorted(counts.items()) if f == file],
              "protocol_definitions":[r for r in definitions if r[0] == file]} for file in range(len(names))]
    return W.summarize(parts)
