#!/usr/bin/env python3
"""Byte-oracle check of physical code atoms and method-owned A0 rows."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import verify_definition_projections as common

ROOT = common.ROOT
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT = ROOT / "artifacts/mdd-026/code-item-audit" / STAMP
common.OUT = OUT
CASES = {
    "classic": ("tests/fixtures/references/generated/classic-035.dex", "076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8"),
    "shared": ("tests/fixtures/references/generated/shared-code-035.dex", "22eb2d4020f172334a99f5c75538af5f2b3e80673adb11803b368cc68aaec0ab"),
}
TRY = "tests/fixtures/instructions/generated/try-catch-all.dex"
COLUMNS = ["file_id", "method_idx", "code_off", "registers_size", "ins_size", "outs_size", "tries_size",
           "debug_info_off", "insns_size", "insns_off", "tries_off", "handlers_off"]


def oracle_class():
    path = ROOT / "tests/fixtures/references/oracle.py"
    spec = importlib.util.spec_from_file_location("mdd_code_independent_oracle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Oracle


def raw_fields(data, offset):
    common.require(0 <= offset <= len(data) - 16 and offset % 4 == 0, "invalid raw code offset")
    registers, ins, outs, tries, debug, size = struct.unpack_from("<HHHHII", data, offset)
    insns_off = offset + 16
    insns_end = insns_off + size * 2
    common.require(insns_end <= len(data), "raw insns outside fixture")
    tries_off = insns_end + (size % 2) * 2 if tries else None
    handlers_off = tries_off + tries * 8 if tries else None
    if tries:
        common.require(handlers_off < len(data), "raw handlers outside fixture")
    return {"code_off":offset, "registers_size":registers, "ins_size":ins, "outs_size":outs,
            "tries_size":tries, "debug_info_off":debug, "insns_size":size, "insns_off":insns_off,
            "tries_off":tries_off, "handlers_off":handlers_off}


def native_fields(item):
    code = item["data"]
    offset = int(code["raw_range"]["byte_offset"])
    size = code["insns_size_code_units"]
    tries = len(code["tries"])
    tries_off = int(code["insns_range"]["byte_offset"]) + size * 2 + (size % 2) * 2 if tries else None
    return {"code_off":offset, "registers_size":code["registers_size"], "ins_size":code["ins_size"],
            "outs_size":code["outs_size"], "tries_size":tries,
            "debug_info_off":int(code["debug_info_byte_offset"]) if code["debug_info_byte_offset"] else 0,
            "insns_size":size, "insns_off":int(code["insns_range"]["byte_offset"]),
            "tries_off":tries_off, "handlers_off":tries_off + tries * 8 if tries else None}


def compare_rows(actual, expected):
    common.require(actual == expected, "code rows, ordering, NULL or multiplicity differ")


def parse_hex_table(raw):
    rows = common.table(raw, COLUMNS)
    return [{key:None if value == "N" else int(bytes.fromhex(value).decode("ascii")) for key, value in row.items()}
            for row in rows]


def map_code_start(data):
    map_off = struct.unpack_from("<I", data, 52)[0]
    count = struct.unpack_from("<I", data, map_off)[0]
    entries = [struct.unpack_from("<HHII", data, map_off + 4 + index * 12) for index in range(count)]
    code = [(size, offset) for kind, unused, size, offset in entries if kind == 0x2001 and unused == 0]
    common.require(len(code) == 1 and code[0][0] == 1, "try fixture code map differs")
    return code[0][1]


def main():
    common.require(common.A0.is_file() and common.digest(common.A0) == common.A0_SHA, "A0 identity mismatch")
    manifest = json.loads((ROOT / "tests/fixtures/instructions/manifest.json").read_text(encoding="utf-8"))
    record = [item for item in manifest["files"] if item["path"] == "try-catch-all.dex"]
    common.require(len(record) == 1, "missing unique pre-registered try fixture")
    fixtures = {name:(path, sha) for name, (path, sha) in CASES.items()}
    fixtures["physical-try"] = (TRY, record[0]["sha256"])
    sources = ["conformance/facts/verify_code_item_atoms.py", "conformance/facts/native_probe.rs",
               "conformance/facts/verify_definition_projections.py", "tests/fixtures/references/oracle.py",
               "tests/fixtures/instructions/manifest.json", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
    for package in ["mdd-dex", "mdd-input", "mdd-types", "mdd-facts"]:
        sources.append(f"crates/{package}/Cargo.toml")
        sources.extend(path.relative_to(ROOT).as_posix() for path in sorted((ROOT / "crates" / package / "src").rglob("*.rs")))
    identities = {path:common.digest(ROOT / path) for path in sources}
    build = common.command("build", ["cargo", "build", "-p", "mdd-facts", "--lib", "--jobs", "1",
                                     "--locked", "--offline", "--message-format=json"])
    libraries = {}
    for line in build.splitlines():
        artifact = json.loads(line)
        if artifact.get("reason") == "compiler-artifact":
            filenames = [name for name in artifact.get("filenames", []) if name.endswith(".rlib")]
            if len(filenames) == 1:
                libraries[artifact["target"]["name"]] = filenames[0]
    exe = OUT / "code_item_atoms_probe.exe"
    argv = ["rustc", "--edition=2024", "--crate-name", "mdd_code_atoms_probe", "conformance/facts/native_probe.rs",
            "-L", "dependency=target/debug/deps", "-o", exe]
    for name in ["mdd_dex", "mdd_facts", "mdd_input", "mdd_types", "serde_json"]:
        common.require(name in libraries, "missing Cargo artifact " + name)
        argv += ["--extern", name + "=" + libraries[name]]
    common.command("compile", argv)
    binary_sha = common.digest(exe)
    expressions = [f'''CASE WHEN "{col}" IS NULL THEN 'N' ELSE hex(CAST("{col}" AS TEXT)) END AS "{col}"'''
                   for col in COLUMNS]
    sql = "SELECT " + ",".join(expressions) + " FROM code_items ORDER BY method_idx"
    Oracle = oracle_class()
    result = []
    controls = []
    for name, (path, sha) in fixtures.items():
        data = (ROOT / path).read_bytes()
        common.require(hashlib.sha256(data).hexdigest() == sha, "fixture identity mismatch: " + name)
        output = json.loads(common.command("native-" + name, [exe, ROOT / path]))
        common.require(output["probe_complete"] and output["operation_status"] == "ok", "native terminal incomplete")
        occurrences = output["dex_occurrences"]
        common.require(len(occurrences) == 1, "unexpected DEX occurrences")
        occurrence = occurrences[0]
        common.require(occurrence["source"]["content_id"] == "sha256:" + sha, "source hash mismatch")
        common.require(occurrence["code"]["source"] == occurrence["source"]
                       and occurrence["raw_code_evidence"]["source"] == occurrence["source"], "source binding mismatch")
        items = {int(item["data"]["raw_range"]["byte_offset"]):item for item in occurrence["code"]["items"]}
        common.require(len(items) == len(occurrence["code"]["items"]), "duplicate physical code starts")
        for offset, item in items.items():
            common.require(native_fields(item) == raw_fields(data, offset), "native code atoms differ from bytes")
        if name == "physical-try":
            offset = map_code_start(data)
            common.require(set(items) == {offset}, "physical map start differs")
            code = raw_fields(data, offset)
            common.require(code["tries_size"] > 0 and code["tries_off"] is not None
                           and code["handlers_off"] is not None, "try fixture lacks non-null offsets")
            common.require(not occurrence["definitions"]["method_definitions"], "try fixture unexpectedly has owner")
            result.append({"case":name, "fixture":path, "sha256":sha, "physical_items":1,
                           "method_owner_count":0, "native_byte_atoms_equal":True,
                           "non_null_try_handler_offsets":True, "a0_relation_queried":False})
            continue
        reference = Oracle(data)
        expected = []
        for method, owner, flags, offset, class_def in reference.definitions:
            if offset:
                common.require(offset in items, "method body has no physical code item")
                expected.append({"file_id":0, "method_idx":method, **raw_fields(data, offset)})
        expected.sort(key=lambda row:row["method_idx"])
        native_defs = occurrence["definitions"]["method_definitions"]
        native_rows = []
        for method in native_defs:
            if method["body"]["state"] == "present":
                offset = int(method["body"]["code_byte_offset"])
                native_rows.append({"file_id":0, "method_idx":method["method_idx"], **native_fields(items[offset])})
        native_rows.sort(key=lambda row:row["method_idx"])
        compare_rows(native_rows, expected)
        for entry in occurrence["raw_code_evidence"]["methods"]:
            if entry["insns_range"] is not None:
                at = int(entry["insns_range"]["byte_offset"])
                length = int(entry["insns_range"]["byte_length"])
                common.require(entry["sha256"] == hashlib.sha256(data[at:at+length]).hexdigest(), "raw insns hash mismatch")
            else:
                common.require(entry["sha256"] is None, "no body projected as empty hash")
        a0 = parse_hex_table(common.command("a0-" + name, [common.A0, "--threads", "1", "query", "--input", ROOT / path, "--sql", sql]))
        compare_rows(a0, expected)
        if name == "shared":
            offsets = [row["code_off"] for row in expected]
            common.require(len(offsets) > len(set(offsets)), "shared code owners missing")
            for label, altered in [("missing_owner", expected[1:]),
                                   ("incorrect_null", [dict(expected[0], tries_off=0), *expected[1:]]),
                                   ("incorrect_code_units", [dict(expected[0], insns_size=expected[0]["insns_size"] * 2), *expected[1:]])]:
                try:
                    compare_rows(altered, expected)
                except RuntimeError as error:
                    common.require(str(error) == "code rows, ordering, NULL or multiplicity differ", "unexpected control error")
                    controls.append(label)
                else:
                    raise RuntimeError("negative control accepted: " + label)
        result.append({"case":name, "fixture":path, "sha256":sha, "physical_items":len(items),
                       "method_owned_rows":len(expected), "a0_rows":len(a0), "columns":COLUMNS,
                       "native_and_a0_equal_byte_oracle":True, "raw_method_insns_fingerprint_equal":True,
                       "null_try_offsets_observed":sum(row["tries_off"] is None for row in expected)})
    common.require(common.digest(common.A0) == common.A0_SHA and common.digest(exe) == binary_sha, "binary changed")
    common.require(all(common.digest(ROOT / path) == sha for path, sha in identities.items()), "source changed")
    common.require(all(common.digest(ROOT / path) == sha for path, sha in fixtures.values()), "fixture changed")
    report = {"schema_version":"mdd.code-item-atoms-differential.v1", "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status":"passed-small-fixtures-only", "task_complete_proven":False, "profile_admitted":False,
              "a0_sha256":common.A0_SHA, "native_binary_sha256":binary_sha, "sources":identities,
              "results":result, "negative_controls_rejected":controls,
              "limits":["12 method-owned code fields assembled only in conformance code; no production compatibility relation implemented.",
                        "Physical try/handler offsets checked for an unowned code item, not an A0 method-owned row.",
                        "Two tiny method fixtures use one raw DEX each; no A0 multi-input or full HostLab audit.",
                        "Actual native source binding and raw instruction hashes verified; ART/complete performance not qualified."]}
    (OUT / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"path":str(OUT.relative_to(ROOT)), "cases":len(result), "a0_relations":2,
                      "negative_controls":len(controls), "task_complete_proven":False}))


if __name__ == "__main__":
    main()
