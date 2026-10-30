#!/usr/bin/env python3
"""Compare bounded method facts and opcode semantics against bytes and A0."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import verify_definition_projections as common

ROOT = common.ROOT
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT = ROOT / "artifacts/mdd-026/method-atom-audit" / STAMP
common.OUT = OUT
CASES = {
    "shared": ("tests/fixtures/references/generated/shared-code-035.dex", "22eb2d4020f172334a99f5c75538af5f2b3e80673adb11803b368cc68aaec0ab"),
    "dynamic": ("tests/fixtures/references/generated/poly-custom-038.dex", "25bc5a03641d31d87212a9a292d798e64c563e2666d03f579e7fc894ac8ee425"),
    "definitions": ("tests/fixtures/definitions/generated/definitions-035.dex", "4e8f9e8deedf44c8793e10d99f2614e0bed705dcac617c0d74137e7b2bd459cc"),
}
COLUMNS = ["file_id", "method_idx", "class_idx", "class_descriptor", "proto_idx", "name", "descriptor",
           "return_descriptor", "param_count", "param_descriptors", "access_flags", "opcode_count", "opcode_hex", "method_kind"]
WIDTHS = {0x0e:1, 0x0f:1, 0x1a:2, 0x1b:3, 0x1c:2, 0x62:2, 0x69:2, 0x70:3, 0x71:3, 0x77:3,
          0xfa:4, 0xfb:4, 0xfc:3, 0xfd:3, 0xfe:2, 0xff:2}


def oracle_class():
    path = ROOT / "tests/fixtures/references/oracle.py"
    spec = importlib.util.spec_from_file_location("mdd_method_independent_oracle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    class Oracle(module.Oracle):
        def instructions(self, words, base):
            result = []
            pc = 0
            while pc < len(words):
                opcode = words[pc] & 255
                width = WIDTHS.get(opcode)
                common.require(width is not None and pc + width <= len(words), "unsupported fixture opcode/width")
                result.append({"pc":pc, "opcode":opcode, "width":width})
                pc += width
            return result
    return Oracle


def reference_rows(reference):
    definitions = {method:(flags, offset) for method, owner, flags, offset, class_def in reference.definitions}
    rows = []
    for index, (owner, name, ret, params, proto, class_idx) in enumerate(reference.methods):
        definition = definitions.get(index)
        flags, offset = definition if definition is not None else (None, None)
        kind = None if flags is None else "direct" if flags & (8 | 2 | 0x10000) else "virtual"
        if flags is None:
            count, hexadecimal = None, None
        elif offset == 0:
            common.require(bool(flags & (0x100 | 0x400)), "concrete definition has no code")
            count, hexadecimal = 0, ""
        else:
            instructions = reference.code[offset]["instructions"]
            count = len(instructions)
            hexadecimal = " ".join(f"{item['opcode']:02x}" for item in instructions)
        rows.append({"file_id":0, "method_idx":index, "class_idx":class_idx, "class_descriptor":owner,
                     "proto_idx":proto, "name":name, "descriptor":owner + "->" + name + "(" + "".join(params) + ")" + ret,
                     "return_descriptor":ret, "param_count":len(params), "param_descriptors":",".join(params),
                     "access_flags":flags, "opcode_count":count, "opcode_hex":hexadecimal, "method_kind":kind})
    return rows


def native_rows(occurrence):
    definitions = {item["method_idx"]:item for item in occurrence["definitions"]["method_definitions"]}
    code = {int(item["data"]["raw_range"]["byte_offset"]):item["data"] for item in occurrence["code"]["items"]}
    rows = []
    for reference in occurrence["definitions"]["method_references"]:
        index = reference["method_idx"]
        definition = definitions.get(index)
        if definition is None:
            flags, kind, count, hexadecimal = None, None, None, None
        else:
            flags, kind = definition["access_flags"], definition["kind"]
            body = definition["body"]
            if body["state"] in ["native", "abstract"]:
                count, hexadecimal = 0, ""
            else:
                common.require(body["state"] == "present", "unknown body state")
                instructions = code[int(body["code_byte_offset"])]["instructions"]
                count = len(instructions)
                hexadecimal = " ".join(f"{item['opcode']:02x}" for item in instructions)
        params = reference["parameter_descriptors"]
        rows.append({"file_id":0, "method_idx":index, "class_idx":reference["class_idx"],
                     "class_descriptor":reference["class_descriptor"], "proto_idx":reference["proto_idx"],
                     "name":reference["method_name"], "descriptor":reference["descriptor"],
                     "return_descriptor":reference["return_descriptor"], "param_count":len(params),
                     "param_descriptors":",".join(params), "access_flags":flags, "opcode_count":count,
                     "opcode_hex":hexadecimal, "method_kind":kind})
    return rows


def compare_rows(actual, expected):
    common.require(actual == expected, "method rows/order/NULL/multiplicity differ")


def decode_a0(raw):
    rows = common.table(raw, COLUMNS)
    nums = {"file_id", "method_idx", "class_idx", "proto_idx", "param_count", "access_flags", "opcode_count"}
    result = []
    for row in rows:
        converted = {}
        for name, text in row.items():
            value = None if text == "N" else bytes.fromhex(text).decode("utf-8", "strict")
            converted[name] = int(value) if value is not None and name in nums else value
        result.append(converted)
    return result


def main():
    common.require(common.A0.is_file() and common.digest(common.A0) == common.A0_SHA, "A0 identity mismatch")
    sources = ["conformance/facts/verify_method_atoms.py", "conformance/facts/native_probe.rs",
               "conformance/facts/verify_definition_projections.py", "tests/fixtures/references/oracle.py",
               "conformance/manifests/relations.json", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
    for package in ["mdd-dex", "mdd-input", "mdd-types", "mdd-facts"]:
        sources.append(f"crates/{package}/Cargo.toml")
        sources.extend(path.relative_to(ROOT).as_posix() for path in sorted((ROOT / "crates" / package / "src").rglob("*.rs")))
    identities = {path:common.digest(ROOT / path) for path in sources}
    build = common.command("build", ["cargo", "build", "-p", "mdd-facts", "--lib", "--jobs", "1",
                                     "--locked", "--offline", "--message-format=json"])
    libs = {}
    for line in build.splitlines():
        artifact = json.loads(line)
        if artifact.get("reason") == "compiler-artifact":
            files = [name for name in artifact.get("filenames", []) if name.endswith(".rlib")]
            if len(files) == 1:
                libs[artifact["target"]["name"]] = files[0]
    exe = OUT / "method_atoms_probe.exe"
    argv = ["rustc", "--edition=2024", "--crate-name", "mdd_method_atoms_probe", "conformance/facts/native_probe.rs",
            "-L", "dependency=target/debug/deps", "-o", exe]
    for name in ["mdd_dex", "mdd_facts", "mdd_input", "mdd_types", "serde_json"]:
        common.require(name in libs, "missing Cargo artifact " + name)
        argv += ["--extern", name + "=" + libs[name]]
    common.command("compile", argv)
    binary_sha = common.digest(exe)
    expr = [f'''CASE WHEN "{col}" IS NULL THEN 'N' ELSE hex(CAST("{col}" AS TEXT)) END AS "{col}"''' for col in COLUMNS]
    # Qualify the source column: the output alias is hex text and sorts lexically.
    sql = "SELECT " + ",".join(expr) + " FROM methods AS m ORDER BY m.method_idx"
    Oracle = oracle_class()
    result, controls = [], []
    for name, (path, sha) in CASES.items():
        raw = (ROOT / path).read_bytes()
        common.require(hashlib.sha256(raw).hexdigest() == sha, "fixture identity mismatch")
        oracle = Oracle(raw)
        expected = reference_rows(oracle)
        output = json.loads(common.command("native-" + name, [exe, ROOT / path]))
        common.require(output["probe_complete"] and output["operation_status"] == "ok"
                       and len(output["dex_occurrences"]) == 1, "native terminal incomplete")
        occurrence = output["dex_occurrences"][0]
        common.require(occurrence["source"]["content_id"] == "sha256:" + sha
                       and occurrence["code"]["source"] == occurrence["source"], "source binding differs")
        native = native_rows(occurrence)
        compare_rows(native, expected)
        a0 = decode_a0(common.command("a0-" + name, [common.A0, "--threads", "1", "query", "--input", ROOT / path, "--sql", sql]))
        compare_rows(a0, expected)
        for row in native:
            common.require(all(type(row[col]) is int and 0 <= row[col] <= 0xffffffff
                               for col in ["file_id", "method_idx", "class_idx", "proto_idx", "param_count"]), "UInt32 type differs")
        if name == "shared":
            codes = [x for x in occurrence["definitions"]["method_definitions"] if x["body"]["state"] == "present"]
            offsets = [x["body"]["code_byte_offset"] for x in codes]
            common.require(len(offsets) > len(set(offsets)), "fixture has no shared code")
            no_body = next(row for row in expected if row["access_flags"] is not None and row["opcode_count"] == 0)
            reference = next(row for row in expected if row["access_flags"] is None)
            common.require(no_body["opcode_hex"] == "" and reference["opcode_count"] is None
                           and reference["opcode_hex"] is None, "no-body/reference boundary differs")
            variants = [
                ("missing_shared_owner", [row for row in expected if row["method_idx"] != 1]),
                ("no_body_becomes_null", [dict(row, opcode_count=None, opcode_hex=None) if row == no_body else row for row in expected]),
                ("reference_becomes_empty", [dict(row, opcode_count=0, opcode_hex="") if row == reference else row for row in expected]),
                ("code_units_as_instruction_count", [dict(expected[0], opcode_count=25), *expected[1:]]),
            ]
            for label, altered in variants:
                try:
                    compare_rows(altered, expected)
                except RuntimeError as error:
                    common.require(str(error) == "method rows/order/NULL/multiplicity differ", "unexpected control failure")
                    controls.append(label)
                else:
                    raise RuntimeError("negative control accepted: " + label)
        if name == "dynamic":
            params = next(row for row in expected if row["param_count"] == 3)
            common.require(params["param_descriptors"].count(",") == 2, "three ordered parameters missing")
            altered = [dict(row, param_descriptors=",".join(reversed(row["param_descriptors"].split(",")))) if row == params else row for row in expected]
            try:
                compare_rows(altered, expected)
            except RuntimeError as error:
                common.require(str(error) == "method rows/order/NULL/multiplicity differ", "unexpected parameter control")
                controls.append("reversed_parameters")
            else:
                raise RuntimeError("parameter order negative control accepted")
        result.append({"case":name, "fixture":path, "sha256":sha, "rows":len(expected), "columns":COLUMNS,
                       "native_and_a0_equal_byte_oracle":True,
                       "reference_only_null_rows":sum(row["access_flags"] is None for row in expected),
                       "defined_no_body_empty_rows":sum(row["access_flags"] is not None and row["opcode_count"] == 0 for row in expected),
                       "multi_parameter_rows":sum(row["param_count"] > 1 for row in expected)})
    common.require(common.digest(common.A0) == common.A0_SHA and common.digest(exe) == binary_sha, "binary changed")
    common.require(all(common.digest(ROOT / path) == sha for path, sha in identities.items()), "source changed")
    common.require(all(common.digest(ROOT / path) == sha for path, sha in CASES.values()), "fixture changed")
    report = {"schema_version":"mdd.method-atoms-differential.v1", "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status":"passed-small-fixtures-only", "task_complete_proven":False, "profile_admitted":False,
              "a0_sha256":common.A0_SHA, "native_binary_sha256":binary_sha, "sources":identities,
              "results":result, "negative_controls_rejected":controls,
              "limits":["14 compatibility values assembled by the conformance driver, not a production methods relation.",
                        "Opcode width oracle covers only opcodes present in three tiny synthetic fixtures.",
                        "A0 queries are single-input with explicit order; no multi-input, non-ASCII or full HostLab qualification."]}
    (OUT / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"path":str(OUT.relative_to(ROOT)), "cases":len(result), "rows":sum(x["rows"] for x in result),
                      "negative_controls":len(controls), "task_complete_proven":False}))


if __name__ == "__main__":
    main()
