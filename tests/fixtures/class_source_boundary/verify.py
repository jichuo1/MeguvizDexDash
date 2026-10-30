#!/usr/bin/env python3
"""Compare class NULL, empty, non-scalar and cross-source identities."""
import datetime
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT / "conformance/facts"))
import verify_definition_projections as common

STAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT = ROOT / "artifacts/mdd-026/class-source-audit" / STAMP
common.OUT = OUT
SDK = Path(r"C:\Users\Administrator\AppData\Local\Android\Sdk\build-tools\37.0.0\dexdump.exe")
SDK_SHA = "f870af85191214f8f59d78e6a27748f00e724bbcce362115347014419969bcce"
CASES = ["null-source", "empty-source", "surrogate-source", "root-empty-source"]
COLUMNS = ["file_id", "class_def_idx", "class_idx", "descriptor", "access_flags", "superclass_descriptor", "interface_count", "source_file"]


def oracle(data, file_id):
    common.require(data[:8] == b"dex\n035\0" and len(data) >= 112, "invalid DEX header")
    common.require(hashlib.sha1(data[32:]).digest() == data[12:32], "signature mismatch")
    common.require(zlib.adler32(data[12:]) & 0xffffffff == struct.unpack_from("<I", data, 8)[0], "checksum mismatch")
    header = struct.unpack_from("<20I", data, 32)
    common.require(header[0] == len(data) and header[16] == 1, "fixture size or class count differs")
    strings = []
    for index in range(header[6]):
        at = struct.unpack_from("<I",data,header[7]+index*4)[0]
        common.require(at < len(data) and data[at] < 128, "unexpected string size encoding")
        size, at = data[at], at+1
        end = data.find(b"\0",at)
        common.require(end >= at, "unterminated string")
        raw = data[at:end]
        text = raw.decode("utf-8","surrogatepass")
        utf16 = text.encode("utf-16-le","surrogatepass")
        units = [int.from_bytes(utf16[n:n+2],"little") for n in range(0,len(utf16),2)]
        common.require(len(units) == size, "string length differs")
        strings.append({"raw":raw.hex(),"units":units,"text":text})
    types = [struct.unpack_from("<I",data,header[9]+index*4)[0] for index in range(header[8])]
    class_idx, flags, parent_idx, interfaces, source_idx, annotations, class_data, static = struct.unpack_from("<8I",data,header[17])
    common.require(class_idx < len(types) and (parent_idx == 0xffffffff or parent_idx < len(types)), "invalid type index")
    common.require(source_idx == 0xffffffff or source_idx < len(strings), "source index outside string pool")
    source = None if source_idx == 0xffffffff else strings[source_idx]
    strict = {"status":"absent"} if source is None else None
    if source is not None:
        try:
            source["text"].encode("utf-8","strict")
            strict = {"status":"scalar","value":source["text"]}
        except UnicodeEncodeError:
            strict = {"status":"non_scalar"}
    return {"file_id":file_id,"class_def_idx":0,"class_idx":class_idx,
            "descriptor":strings[types[class_idx]]["text"],"access_flags":flags,
            "superclass_descriptor":None if parent_idx == 0xffffffff else strings[types[parent_idx]]["text"],
            "interface_count":0 if interfaces == 0 else struct.unpack_from("<I",data,interfaces)[0],
            "source_file_raw_hex":None if source is None else source["raw"],
            "source_file_utf16":None if source is None else source["units"],"source_file_strict":strict}


def a0_row(expected):
    row = {}
    for col in COLUMNS:
        if col == "source_file":
            value = expected["source_file_raw_hex"]
            row[col] = "N" if value is None else value.upper()
        else:
            value = expected[col]
            row[col] = "N" if value is None else str(value).encode("utf-8").hex().upper()
    return row


def compare(actual, expected):
    common.require(actual == expected,"class source rows/order/NULL differ")


def run_raw(label, argv):
    folder = OUT / label
    folder.mkdir(parents=True,exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    begin = time.monotonic()
    proc = subprocess.run([str(value) for value in argv],cwd=ROOT,capture_output=True,timeout=90)
    (folder / "stdout.txt").write_bytes(proc.stdout)
    (folder / "stderr.txt").write_bytes(proc.stderr)
    (folder / "record.json").write_text(json.dumps({"argv":[str(v) for v in argv],"started_utc":started,
        "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"elapsed_seconds":time.monotonic()-begin,
        "exit_code":proc.returncode,"stdout_sha256":hashlib.sha256(proc.stdout).hexdigest(),
        "stderr_sha256":hashlib.sha256(proc.stderr).hexdigest(),"scope":"small synthetic development conformance"},indent=2)+"\n",encoding="utf-8")
    return proc


def main():
    common.require(common.A0.is_file() and common.digest(common.A0) == common.A0_SHA,"A0 identity mismatch")
    common.require(SDK.is_file() and common.digest(SDK) == SDK_SHA,"SDK identity mismatch")
    fixture_base = ROOT / "tests/fixtures/class_source_boundary"
    manifest = json.loads((fixture_base / "manifest.json").read_text(encoding="utf-8"))
    fixtures = {item["id"]:item for item in manifest["files"]}
    common.require(set(fixtures) == set(CASES+['bad-source-index']),"fixture manifest differs")
    sources = ["tests/fixtures/class_source_boundary/generate.py","tests/fixtures/class_source_boundary/probe.rs",
               "tests/fixtures/class_source_boundary/verify.py","tests/fixtures/class_source_boundary/manifest.json",
               "conformance/facts/verify_definition_projections.py","Cargo.toml","Cargo.lock","rust-toolchain.toml"]
    for package in ["mdd-dex","mdd-input","mdd-types","mdd-facts"]:
        sources.append(f"crates/{package}/Cargo.toml")
        sources.extend(path.relative_to(ROOT).as_posix() for path in sorted((ROOT/"crates"/package/"src").rglob("*.rs")))
    identities = {path:common.digest(ROOT/path) for path in sources}
    build = common.command("build",["cargo","build","-p","mdd-facts","--lib","--jobs","1","--locked","--offline","--message-format=json"])
    libs = {}
    for line in build.splitlines():
        artifact = json.loads(line)
        if artifact.get("reason") == "compiler-artifact":
            files = [name for name in artifact.get("filenames",[]) if name.endswith(".rlib")]
            if len(files) == 1:
                libs[artifact["target"]["name"]] = files[0]
    exe = OUT / "class_source_probe.exe"
    argv = ["rustc","--edition=2024","--crate-name","mdd_class_source_probe",sources[1],"-L","dependency=target/debug/deps","-o",exe]
    for name in ["mdd_dex","mdd_facts","mdd_input","mdd_types","serde_json"]:
        common.require(name in libs,"missing Cargo artifact " + name)
        argv += ["--extern",name+"="+libs[name]]
    common.command("compile",argv)
    binary_sha = common.digest(exe)
    paths = [fixture_base/fixtures[case]["path"] for case in CASES]
    expected = []
    sdk_observations = []
    for index,(case,path) in enumerate(zip(CASES,paths)):
        raw = path.read_bytes()
        common.require(hashlib.sha256(raw).hexdigest() == fixtures[case]["sha256"],"fixture identity differs")
        expected.append(oracle(raw,index))
        sdk = run_raw("sdk-"+case,[SDK,"-d",path])
        sdk_observations.append({"case":case,"exit_code":sdk.returncode})
    native = json.loads(common.command("native-multi",[exe,*paths]))
    occurrences = native["occurrences"]
    common.require(native["probe_complete"] and native["operation_status"] == "ok" and len(occurrences) == 4,
                   "native terminal incomplete")
    common.require([x["selected"]["file_id"] for x in occurrences] == list(range(4))
                   and len({x["source"]["dex_occurrence_id"] for x in occurrences}) == 4,
                   "source occurrence collapsed")
    for item, ref, case in zip(occurrences,expected,CASES):
        common.require(item["source"]["content_id"] == "sha256:" + fixtures[case]["sha256"]
                       and len(item["classes"]) == 1,"source content/class multiplicity differs")
        actual = item["classes"][0]
        fact = actual["fact"]
        common.require(fact["class_def_idx"] == ref["class_def_idx"] and fact["class_idx"] == ref["class_idx"]
                       and fact["descriptor"] == ref["descriptor"] and fact["access_flags"] == ref["access_flags"]
                       and fact["superclass_descriptor"] == ref["superclass_descriptor"],"class fact differs")
        if ref["source_file_raw_hex"] is None:
            common.require(fact["source_file"] is None and fact["source_file_idx"] is None,"NULL source collapsed")
        else:
            common.require(bytes(fact["source_file"]["raw_mutf8"]).hex() == ref["source_file_raw_hex"]
                           and fact["source_file"]["utf16_units"] == ref["source_file_utf16"],"source raw/UTF16 differs")
        common.require(actual["source_file_strict"] == ref["source_file_strict"],"strict source conversion differs")
    common.require(expected[0]["source_file_strict"]["status"] == "absent"
                   and expected[1]["source_file_strict"] == {"status":"scalar","value":""}
                   and expected[2]["source_file_strict"]["status"] == "non_scalar"
                   and expected[3]["superclass_descriptor"] is None,"expected boundary missing")
    common.require(len({ref["descriptor"] for ref in expected[:3]}) == 1,"duplicate descriptor boundary missing")
    expressions = [f'''CASE WHEN c."{col}" IS NULL THEN 'N' ELSE hex(CAST(c."{col}" AS TEXT)) END AS "{col}"''' for col in COLUMNS]
    sql = "SELECT " + ",".join(expressions) + " FROM classes AS c ORDER BY c.file_id,c.class_def_idx"
    inputs = [value for path in paths for value in ["--input",path]]
    a0 = common.table(common.command("a0-multi",[common.A0,"--threads","1","query",*inputs,"--sql",sql]),COLUMNS)
    compare(a0,[a0_row(ref) for ref in expected])
    mutations = [("null_to_empty",[dict(expected[0],source_file_raw_hex=""),*expected[1:]]),
                 ("empty_to_null",[expected[0],dict(expected[1],source_file_raw_hex=None),*expected[2:]]),
                 ("surrogate_to_replacement",[*expected[:2],dict(expected[2],source_file_raw_hex="efbfbd"),expected[3]]),
                 ("collapsed_duplicate_descriptor",[expected[0],expected[3]]),
                 ("swapped_sources",[expected[1],expected[0],*expected[2:]])]
    controls = []
    for label,changed in mutations:
        try:
            compare([a0_row(ref) for ref in changed],[a0_row(ref) for ref in expected])
        except RuntimeError as error:
            common.require(str(error) == "class source rows/order/NULL differ","unexpected mutation terminal")
            controls.append(label)
        else:
            raise RuntimeError("mutation accepted: " + label)
    bad = fixtures["bad-source-index"]
    bad_path = fixture_base/bad["path"]
    raw_bad = bad_path.read_bytes()
    common.require(hashlib.sha256(raw_bad).hexdigest() == bad["sha256"],"bad fixture changed")
    try:
        oracle(raw_bad,0)
    except RuntimeError as error:
        common.require(str(error) == "source index outside string pool","bad oracle terminal differs")
    else:
        raise RuntimeError("bad source index passed byte oracle")
    native_bad = run_raw("native-bad",[exe,bad_path])
    native_bad_json = json.loads(native_bad.stdout)
    common.require(native_bad.returncode != 0 and native_bad_json["operation_status"] == "error"
                   and native_bad_json["error"]["code"] == "INVALID_INPUT","bad source index native terminal differs")
    sdk_bad = run_raw("sdk-bad",[SDK,"-d",bad_path])
    a0_bad = run_raw("a0-bad",[common.A0,"--threads","1","query","--input",bad_path,"--sql",sql])
    common.require(common.digest(common.A0) == common.A0_SHA and common.digest(SDK) == SDK_SHA
                   and common.digest(exe) == binary_sha,"binary changed")
    common.require(all(common.digest(ROOT/path) == sha for path,sha in identities.items()),"source changed")
    common.require(all(common.digest(fixture_base/item["path"]) == item["sha256"] for item in fixtures.values()),"fixture changed")
    report = {"schema_version":"mdd.class-source-boundary.v1","created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status":"passed-small-source-boundaries","task_complete_proven":False,"profile_admitted":False,
              "a0_sha256":common.A0_SHA,"sdk_dexdump_sha256":SDK_SHA,"native_binary_sha256":binary_sha,"sources":identities,
              "fixtures":[{"id":case,"sha256":fixtures[case]["sha256"],"oracle":ref} for case,ref in zip(CASES,expected)],
              "sdk_observations":sdk_observations,"a0_ordered_rows":len(a0),"negative_controls_rejected":controls,
              "bad_source_index":{"fixture_sha256":bad["sha256"],"native_exit":native_bad.returncode,
                                  "native_error":native_bad_json["error"],"sdk_exit_observed":sdk_bad.returncode,"a0_exit_observed":a0_bad.returncode},
              "limits":["Only small synthetic DEX; production classes compatibility relation not assembled.",
                        "A0 hex(CAST(source_file AS TEXT)) exposes MUTF8 bytes, not valid ordinary UTF8 for isolated surrogate.",
                        "Native strict conversion explicitly rejects non-scalar source text, preserving UTF16 units and raw MUTF8.",
                        "SDK exit codes are format observations, not full ART/device qualification."]}
    (OUT/"result.json").write_text(json.dumps(report,indent=2,ensure_ascii=True)+"\n",encoding="utf-8")
    print(json.dumps({"path":str(OUT.relative_to(ROOT)),"source_occurrences":4,"a0_rows":len(a0),
                      "negative_controls":len(controls),"sdk_valid_exit_codes":[x["exit_code"] for x in sdk_observations],
                      "bad_native_exit":native_bad.returncode,"bad_sdk_exit":sdk_bad.returncode,"bad_a0_exit":a0_bad.returncode,
                      "task_complete_proven":False}))


if __name__ == "__main__":
    main()
