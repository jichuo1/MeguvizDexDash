#!/usr/bin/env python3
"""Compare bounded native header facts to source bytes and fixed A0 rows."""
import datetime
import hashlib
import json
from pathlib import Path
import struct
import zlib
import verify_definition_projections as common

ROOT = common.ROOT
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT = ROOT / "artifacts/mdd-026/header-audit" / STAMP
common.OUT = OUT
CASES = {
    "definitions-035": ("tests/fixtures/definitions/generated/definitions-035.dex", common.FIXTURE_SHA),
    "classic-035": ("tests/fixtures/references/generated/classic-035.dex", "076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8"),
    "dynamic-038": ("tests/fixtures/references/generated/poly-custom-038.dex", "25bc5a03641d31d87212a9a292d798e64c563e2666d03f579e7fc894ac8ee425"),
}
WORDS = ["file_size", "header_size", "endian_tag", "link_size", "link_off", "map_off",
         "string_count", "string_ids_off", "type_count", "type_ids_off", "proto_count", "proto_ids_off",
         "field_count", "field_ids_off", "method_count", "method_ids_off", "class_count", "class_defs_off",
         "data_size", "data_off"]
TABLES = [("string", "string_ids"), ("type", "type_ids"), ("proto", "proto_ids"),
          ("field", "field_ids"), ("method", "method_ids"), ("class", "class_defs")]
COLUMNS = ["byte_len", "dex_version", "checksum", "signature_hex", *WORDS]


def oracle(data):
    common.require(len(data) >= 112 and data[:4] == b"dex\n" and data[7] == 0, "invalid fixture header")
    words = dict(zip(WORDS, struct.unpack_from("<20I", data, 32)))
    common.require(words["file_size"] == len(data) and words["header_size"] == 112, "declared size mismatch")
    common.require(words["endian_tag"] == 0x12345678, "non-little-endian fixture")
    checksum = struct.unpack_from("<I", data, 8)[0]
    signature = data[12:32].hex()
    common.require(checksum == zlib.adler32(data[12:]) & 0xffffffff, "checksum mismatch")
    common.require(signature == hashlib.sha1(data[32:]).hexdigest(), "signature mismatch")
    return {"byte_len":len(data), "dex_version":data[4:7].decode("ascii"), "checksum":checksum,
            "signature_hex":signature, **words}


def native_values(item):
    header = item["header"]
    common.require(header["checksum_verified"] and header["signature_verified"] and header["endian"] == "little",
                   "native header verification absent")
    values = {"byte_len":item["byte_len"], "dex_version":header["version"],
              "checksum":header["declared_checksum"], "signature_hex":header["declared_signature_sha1"],
              "file_size":int(header["file_size"]), "header_size":int(header["header_range"]["byte_length"]),
              "endian_tag":0x12345678,
              "link_size":int(header["link_range"]["byte_length"]) if header["link_range"] else 0,
              "link_off":int(header["link_range"]["byte_offset"]) if header["link_range"] else 0,
              "map_off":int(next(x["byte_offset"] for x in header["map"] if x["name"] == "map_list")),
              "data_size":int(header["data_range"]["byte_length"]),
              "data_off":int(header["data_range"]["byte_offset"])}
    tables = {item["name"]:item for item in header["tables"]}
    for prefix, name in TABLES:
        values[prefix + "_count"] = tables[name]["count"]
        values[name + "_off"] = int(tables[name]["range"]["byte_offset"])
    return values


def compare_native(item, expected):
    common.require(native_values(item) == expected, "native versus source bytes mismatch")


def main():
    common.require(common.A0.is_file() and common.digest(common.A0) == common.A0_SHA, "A0 identity mismatch")
    sources = ["conformance/facts/header_byte_probe.rs", "conformance/facts/verify_header_bytes.py",
               "conformance/facts/verify_definition_projections.py", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
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
    exe = OUT / "header_byte_probe.exe"
    argv = ["rustc", "--edition=2024", "--crate-name", "mdd_header_byte_probe", sources[0],
            "-L", "dependency=target/debug/deps", "-o", exe]
    for name in ["mdd_dex", "mdd_facts", "mdd_input", "mdd_types", "serde_json"]:
        common.require(name in libraries, "missing Cargo artifact " + name)
        argv += ["--extern", name + "=" + libraries[name]]
    common.command("compile", argv)
    binary_sha = common.digest(exe)
    expressions = [f'''CASE WHEN "{col}" IS NULL THEN 'N' ELSE hex(CAST("{col}" AS TEXT)) END AS "{col}"'''
                   for col in COLUMNS]
    sql = "SELECT " + ",".join(expressions) + " FROM dex_files"
    results = []
    for name, (path, sha) in CASES.items():
        fixture = ROOT / path
        raw = fixture.read_bytes()
        common.require(hashlib.sha256(raw).hexdigest() == sha, "fixture identity mismatch: " + name)
        expected = oracle(raw)
        native = json.loads(common.command("native-" + name, [exe, fixture]))
        occurrences = native["occurrences"]
        common.require(native["probe_complete"] and native["operation_status"] == "ok" and len(occurrences) == 2,
                       "native terminal incomplete: " + name)
        common.require([x["selected"]["file_id"] for x in occurrences] == [0, 1], "unexpected source file IDs")
        common.require(len({x["source"]["source_occurrence_id"] for x in occurrences}) == 2, "sources collapsed")
        common.require(len({x["source"]["dex_occurrence_id"] for x in occurrences}) == 2, "DEX occurrences collapsed")
        for occurrence in occurrences:
            common.require(occurrence["source"]["content_id"] == "sha256:" + sha, "content identity mismatch")
            compare_native(occurrence, expected)
        rows = common.table(common.command("a0-" + name, [common.A0, "--threads", "1", "query", "--input", fixture,
                                                          "--sql", sql]), COLUMNS)
        common.require(rows == [{col:common.encode(expected[col]) for col in COLUMNS}], "A0 versus source bytes mismatch: " + name)
        common.require(common.digest(fixture) == sha, "fixture changed: " + name)
        results.append({"case":name, "fixture":path, "sha256":sha, "columns_compared":COLUMNS,
                        "native_occurrences":2, "a0_occurrences":1, "byte_oracle_equal":True,
                        "a0_single_input_equal":True})
    sample = bytearray((ROOT / CASES["classic-035"][0]).read_bytes())
    controls = []
    for label, offset in [("checksum_corruption", 8), ("payload_corruption", len(sample)-1)]:
        altered = bytearray(sample)
        altered[offset] ^= 1
        try:
            oracle(altered)
        except RuntimeError as error:
            common.require("checksum mismatch" in str(error), "unexpected negative control error")
            controls.append(label)
        else:
            raise RuntimeError("negative control accepted: " + label)
    altered = bytearray(sample)
    altered[-1] ^= 1
    struct.pack_into("<I", altered, 8, zlib.adler32(altered[12:]) & 0xffffffff)
    try:
        oracle(altered)
    except RuntimeError as error:
        common.require(str(error) == "signature mismatch", "unexpected signature control error")
        controls.append("signature_corruption_with_valid_checksum")
    else:
        raise RuntimeError("signature negative control accepted")
    # Change one actual native field, leaving the separately decoded bytes untouched.
    changed = json.loads(json.dumps(occurrences[0]))
    changed["header"]["declared_checksum"] ^= 1
    try:
        compare_native(changed, expected)
    except RuntimeError as error:
        common.require(str(error) == "native versus source bytes mismatch", "unexpected field control error")
        controls.append("native_field_corruption")
    else:
        raise RuntimeError("native field negative control accepted")
    common.require(common.digest(common.A0) == common.A0_SHA and common.digest(exe) == binary_sha, "binary changed")
    common.require(all(common.digest(ROOT / path) == sha for path, sha in identities.items()), "source changed")
    report = {"schema_version":"mdd.header-byte-differential.v1", "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status":"passed-small-fixtures-only", "task_complete_proven":False, "profile_admitted":False,
              "a0_sha256":common.A0_SHA, "native_binary_sha256":binary_sha, "sources":identities,
              "results":results, "negative_controls_rejected":controls,
              "limits":["24 header/native byte fields only; compatibility row assembly is not implemented by this test.",
                        "A0 queried each fixture once; duplicate source mapping is native-only and not compared to A0 multi-input.",
                        "File ID, string pool numeric ID, source path and entry name are outside the 24-column byte oracle.",
                        "Three tiny fixtures do not qualify all inputs, full HostLab audit or performance."]}
    (OUT / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"path":str(OUT.relative_to(ROOT)), "cases":len(results), "columns":len(COLUMNS),
                      "native_occurrences":sum(item["native_occurrences"] for item in results),
                      "negative_controls":len(controls), "task_complete_proven":False}))


if __name__ == "__main__":
    main()
