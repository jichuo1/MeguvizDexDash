#!/usr/bin/env python3
"""Bounded byte/native/A0 comparison for method-owned try/catch fixtures."""
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
sys.path.insert(0, str(ROOT / "conformance/facts"))
import verify_definition_projections as common

STAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT = ROOT / "artifacts/mdd-026/owned-try-audit" / STAMP
common.OUT = OUT
SDK = Path(r"C:\Users\Administrator\AppData\Local\Android\Sdk\build-tools\37.0.0\dexdump.exe")
SDK_SHA = "f870af85191214f8f59d78e6a27748f00e724bbcce362115347014419969bcce"
COLUMNS = ["file_id", "method_idx", "code_off", "registers_size", "ins_size", "outs_size", "tries_size",
           "debug_info_off", "insns_size", "insns_off", "tries_off", "handlers_off"]


def uleb(data, offset):
    value = 0
    for index in range(5):
        common.require(offset + index < len(data), "truncated LEB")
        byte = data[offset + index]
        value |= (byte & 127) << (7 * index)
        if byte < 128:
            return value, offset + index + 1
    raise RuntimeError("oversized LEB")


def oracle(data):
    common.require(data[:8] == b"dex\n035\x00" and len(data) >= 112, "invalid DEX header")
    common.require(hashlib.sha1(data[32:]).digest() == data[12:32], "signature mismatch")
    common.require(zlib.adler32(data[12:]) & 0xffffffff == struct.unpack_from("<I", data, 8)[0], "checksum mismatch")
    header = struct.unpack_from("<20I", data, 32)
    common.require(header[0] == len(data) and header[16] == 1 and header[14] == 1, "fixture layout differs")
    class_def = struct.unpack_from("<8I", data, header[17])
    at = class_def[6]
    counts = []
    for _ in range(4):
        value, at = uleb(data, at)
        counts.append(value)
    common.require(counts == [0,0,1,0], "fixture method layout differs")
    method, at = uleb(data, at)
    flags, at = uleb(data, at)
    offset, at = uleb(data, at)
    common.require(method == 0 and flags == 9 and offset % 4 == 0, "invalid method ownership")
    map_count = struct.unpack_from("<I", data, header[5])[0]
    entries = [struct.unpack_from("<HHII", data, header[5] + 4 + index * 12) for index in range(map_count)]
    common.require([(size, pos) for kind, unused, size, pos in entries if kind == 0x2001] == [(1, offset)],
                   "method code is not declared physical code start")
    registers, ins, outs, tries, debug, count = struct.unpack_from("<HHHHII", data, offset)
    insns = offset + 16
    words = list(struct.unpack_from("<" + "H" * count, data, insns))
    common.require(words[:4] == [0x0012,0x0027,0x000d,0x000e] and words[4:] in [[], [0]], "unexpected instruction words")
    tries_off = insns + count * 2 + (count % 2) * 2
    start_pc, length, handler_off = struct.unpack_from("<IHH", data, tries_off)
    handlers_off = tries_off + tries * 8
    handlers_count, handler = uleb(data, handlers_off)
    signed_size = data[handler]
    handler += 1
    target, handler = uleb(data, handler)
    common.require(tries == 1 and start_pc == 1 and length == 1 and handler_off == 1
                   and handlers_count == 1 and signed_size == 0, "try handler structure differs")
    common.require(target == 2 and target < count, "handler target outside valid instruction boundary")
    return {"file_id":0, "method_idx":method, "code_off":offset, "registers_size":registers,
            "ins_size":ins, "outs_size":outs, "tries_size":tries, "debug_info_off":debug,
            "insns_size":count, "insns_off":insns, "tries_off":tries_off, "handlers_off":handlers_off,
            "raw_insns_sha256":hashlib.sha256(data[insns:insns+count*2]).hexdigest(),
            "try_start_pc":start_pc, "try_code_units":length, "handler_target_pc":target,
            "padding_bytes":(count % 2)*2}


def run_raw(label, argv):
    folder = OUT / label
    folder.mkdir(parents=True, exist_ok=True)
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    begin = time.monotonic()
    proc = subprocess.run([str(value) for value in argv], cwd=ROOT, capture_output=True, timeout=90)
    (folder / "stdout.txt").write_bytes(proc.stdout)
    (folder / "stderr.txt").write_bytes(proc.stderr)
    record = {"argv":[str(value) for value in argv], "started_utc":start,
              "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "elapsed_seconds":time.monotonic()-begin, "exit_code":proc.returncode,
              "stdout_sha256":hashlib.sha256(proc.stdout).hexdigest(),
              "stderr_sha256":hashlib.sha256(proc.stderr).hexdigest(),
              "scope":"small synthetic conformance; not performance"}
    (folder / "record.json").write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8")
    return proc


def compare_rows(actual, expected):
    common.require(actual == expected, "owned code fields/NULL/offsets differ")


def main():
    common.require(common.A0.is_file() and common.digest(common.A0) == common.A0_SHA, "A0 identity mismatch")
    common.require(SDK.is_file() and common.digest(SDK) == SDK_SHA, "SDK dexdump identity mismatch")
    manifest_path = "tests/fixtures/owned_try/manifest.json"
    manifest = json.loads((ROOT / manifest_path).read_text(encoding="utf-8"))
    fixtures = {Path(item["path"]).name:item for item in manifest["files"]}
    common.require(set(fixtures) == {"owned-try-even.dex", "owned-try-odd.dex", "owned-try-bad-handler.dex"},
                   "fixture manifest differs")
    sources = ["tests/fixtures/owned_try/generate.py", "tests/fixtures/owned_try/verify.py", manifest_path,
               "conformance/facts/native_probe.rs", "conformance/facts/verify_definition_projections.py",
               "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
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
            paths = [value for value in artifact.get("filenames", []) if value.endswith(".rlib")]
            if len(paths) == 1:
                libs[artifact["target"]["name"]] = paths[0]
    executable = OUT / "owned_try_probe.exe"
    argv = ["rustc", "--edition=2024", "--crate-name", "mdd_owned_try_probe", "conformance/facts/native_probe.rs",
            "-L", "dependency=target/debug/deps", "-o", executable]
    for name in ["mdd_dex", "mdd_facts", "mdd_input", "mdd_types", "serde_json"]:
        common.require(name in libs, "missing Cargo artifact " + name)
        argv += ["--extern", name + "=" + libs[name]]
    common.command("compile", argv)
    binary_sha = common.digest(executable)
    expressions = [f'''CASE WHEN "{col}" IS NULL THEN 'N' ELSE hex(CAST("{col}" AS TEXT)) END AS "{col}"''' for col in COLUMNS]
    sql = "SELECT " + ",".join(expressions) + " FROM code_items AS c ORDER BY c.method_idx"
    observations, controls = [], []
    for name in ["owned-try-even.dex", "owned-try-odd.dex"]:
        item = fixtures[name]
        path = ROOT / "tests/fixtures/owned_try" / item["path"]
        data = path.read_bytes()
        common.require(hashlib.sha256(data).hexdigest() == item["sha256"], "fixture hash differs")
        expected = oracle(data)
        sdk = run_raw("sdk-" + name, [SDK, "-d", path])
        common.require(sdk.returncode == 0, "SDK dexdump failed valid fixture; output retained")
        native = json.loads(common.command("native-" + name, [executable, path]))
        common.require(native["probe_complete"] and native["operation_status"] == "ok"
                       and len(native["dex_occurrences"]) == 1, "native terminal incomplete")
        occurrence = native["dex_occurrences"][0]
        common.require(occurrence["source"]["content_id"] == "sha256:" + item["sha256"]
                       and occurrence["source"] == occurrence["code"]["source"]
                       and occurrence["source"] == occurrence["raw_code_evidence"]["source"], "source binding differs")
        methods = occurrence["definitions"]["method_definitions"]
        items = occurrence["code"]["items"]
        common.require(len(methods) == len(items) == 1 and methods[0]["method_idx"] == 0
                       and int(methods[0]["body"]["code_byte_offset"]) == expected["code_off"], "method owner differs")
        code = items[0]["data"]
        common.require(code["registers_size"] == expected["registers_size"] and code["ins_size"] == expected["ins_size"]
                       and code["outs_size"] == expected["outs_size"] and len(code["tries"]) == 1
                       and code["insns_size_code_units"] == expected["insns_size"]
                       and int(code["insns_range"]["byte_offset"]) == expected["insns_off"], "native code atoms differ")
        common.require(code["tries"][0]["start_code_unit"] == expected["try_start_pc"]
                       and code["tries"][0]["code_unit_count"] == expected["try_code_units"]
                       and len(code["handlers"]) == 1
                       and code["handlers"][0]["catch_all_address_code_units"] == expected["handler_target_pc"],
                       "native try/handler differs")
        raw = occurrence["raw_code_evidence"]["methods"]
        common.require(len(raw) == 1 and raw[0]["sha256"] == expected["raw_insns_sha256"], "native code fingerprint differs")
        raw_a0 = common.command("a0-" + name, [common.A0, "--threads", "1", "query", "--input", path, "--sql", sql])
        rows = common.table(raw_a0, COLUMNS)
        actual = [{key:None if value == "N" else int(bytes.fromhex(value).decode("ascii")) for key,value in row.items()} for row in rows]
        expected_row = {column:expected[column] for column in COLUMNS}
        compare_rows(actual, [expected_row])
        for label, altered in [("try_null", [dict(expected_row, tries_off=None)]),
                               ("wrong_handler_offset", [dict(expected_row, handlers_off=expected_row["handlers_off"]+1)]),
                               ("omitted_owner", [])]:
            try:
                compare_rows(altered, [expected_row])
            except RuntimeError as error:
                common.require(str(error) == "owned code fields/NULL/offsets differ", "unexpected negative control")
                controls.append(name + ":" + label)
            else:
                raise RuntimeError("negative control accepted: " + label)
        observations.append({"fixture":name, "sha256":item["sha256"], "sdk_dexdump_exit":sdk.returncode,
                             "byte_oracle":expected, "a0_rows":len(actual), "native_source_bound":True,
                             "native_code_and_A0_equal_byte_oracle":True})
    bad = fixtures["owned-try-bad-handler.dex"]
    bad_path = ROOT / "tests/fixtures/owned_try" / bad["path"]
    bad_bytes = bad_path.read_bytes()
    common.require(hashlib.sha256(bad_bytes).hexdigest() == bad["sha256"], "bad fixture hash differs")
    try:
        oracle(bad_bytes)
    except RuntimeError as error:
        common.require(str(error) == "handler target outside valid instruction boundary", "unexpected bad oracle terminal")
        oracle_failure = str(error)
    else:
        raise RuntimeError("bad handler passed independent byte oracle")
    native_bad = run_raw("native-bad", [executable, bad_path])
    native_terminal = json.loads(native_bad.stdout)
    common.require(native_bad.returncode != 0 and native_terminal["operation_status"] == "error"
                   and native_terminal["error"]["code"] == "INVALID_INPUT", "bad handler native terminal differs")
    sdk_bad = run_raw("sdk-bad", [SDK, "-d", bad_path])
    a0_bad = run_raw("a0-bad", [common.A0, "--threads", "1", "query", "--input", bad_path, "--sql", sql])
    common.require(common.digest(common.A0) == common.A0_SHA and common.digest(SDK) == SDK_SHA
                   and common.digest(executable) == binary_sha, "binary changed")
    common.require(all(common.digest(ROOT / path) == sha for path, sha in identities.items()), "source changed")
    common.require(all(common.digest(ROOT / "tests/fixtures/owned_try" / item["path"]) == item["sha256"]
                       for item in fixtures.values()), "fixture changed")
    report = {"schema_version":"mdd.method-owned-try-differential.v1", "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status":"passed-small-structural-fixtures", "task_complete_proven":False, "profile_admitted":False,
              "a0_sha256":common.A0_SHA, "sdk_dexdump_sha256":SDK_SHA, "native_binary_sha256":binary_sha,
              "sources":identities, "valid":observations, "negative_controls_rejected":controls,
              "bad_handler":{"fixture":bad["path"], "sha256":bad["sha256"], "oracle_error":oracle_failure,
                             "native_exit":native_bad.returncode, "native_error":native_terminal["error"],
                             "sdk_exit_observed":sdk_bad.returncode, "a0_exit_observed":a0_bad.returncode},
              "limits":["Two synthetic method-owned code items, one even and one odd with alignment padding; not broad DEX coverage.",
                        "SDK dexdump success is a file-format observation, not complete ART type-flow or device verification.",
                        "A0 invalid-input terminal is recorded as observed, not normalized or used to excuse native errors.",
                        "No production code_items compatibility relation, full HostLab or performance qualification."]}
    (OUT / "result.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"path":str(OUT.relative_to(ROOT)), "valid_cases":len(observations),
                      "negative_controls":len(controls), "bad_native_exit":native_bad.returncode,
                      "bad_sdk_exit":sdk_bad.returncode, "bad_a0_exit":a0_bad.returncode, "task_complete_proven":False}))


if __name__ == "__main__":
    main()
