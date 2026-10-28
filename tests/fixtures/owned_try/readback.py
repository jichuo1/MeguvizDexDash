#!/usr/bin/env python3
"""Append-only recheck of method-owned try/catch source and process evidence."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import verify as audit


def main():
    audit.common.require(len(sys.argv) == 2, "expected recorded run path")
    base = (audit.ROOT / "artifacts/mdd-026/owned-try-audit").resolve()
    folder = (audit.ROOT / sys.argv[1]).resolve()
    audit.common.require(folder.is_relative_to(base) and folder != base, "run path outside owned-try evidence")
    result_path = folder / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    audit.common.require(not report["task_complete_proven"] and not report["profile_admitted"], "scope overclaimed")
    audit.common.require(audit.common.digest(audit.common.A0) == report["a0_sha256"] == audit.common.A0_SHA
                         and audit.common.digest(audit.SDK) == report["sdk_dexdump_sha256"] == audit.SDK_SHA,
                         "external binary identity changed")
    audit.common.require(audit.common.digest(folder / "owned_try_probe.exe") == report["native_binary_sha256"],
                         "native binary identity changed")
    for path, sha in report["sources"].items():
        audit.common.require(audit.common.digest(audit.ROOT / path) == sha, "source changed: " + path)
    labels = ["build", "compile"]
    for name in ["owned-try-even.dex", "owned-try-odd.dex"]:
        labels.extend(["sdk-" + name, "native-" + name, "a0-" + name])
    labels.extend(["native-bad", "sdk-bad", "a0-bad"])
    exits = {}
    for label in labels:
        path = folder / label
        record = json.loads((path / "record.json").read_text(encoding="utf-8"))
        exits[label] = record["exit_code"]
        for stream in ["stdout", "stderr"]:
            audit.common.require(audit.common.digest(path / (stream + ".txt")) == record[stream + "_sha256"],
                                 "command output changed: " + label + "/" + stream)
        if label not in ["native-bad", "sdk-bad", "a0-bad"]:
            audit.common.require(record["exit_code"] == 0, "valid command failed: " + label)
    gen_path = audit.ROOT / "tests/fixtures/owned_try/generate.py"
    spec = importlib.util.spec_from_file_location("mdd_owned_try_generator", gen_path)
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    manifest = json.loads((audit.ROOT / "tests/fixtures/owned_try/manifest.json").read_text(encoding="utf-8"))
    records = {Path(item["path"]).name:item for item in manifest["files"]}
    for item in report["valid"]:
        name = item["fixture"]
        info = records[name]
        path = audit.ROOT / "tests/fixtures/owned_try" / info["path"]
        raw = path.read_bytes()
        rebuilt, layout = gen.build(name.endswith("odd.dex"), False)
        audit.common.require(raw == rebuilt and hashlib.sha256(raw).hexdigest() == item["sha256"] == info["sha256"]
                             and layout == info["hand_layout"], "valid fixture reproducibility differs")
        expected = audit.oracle(raw)
        audit.common.require(expected == item["byte_oracle"], "byte oracle differs")
        native = json.loads((folder / ("native-" + name) / "stdout.txt").read_text(encoding="utf-8"))
        audit.common.require(native["probe_complete"] and native["operation_status"] == "ok"
                             and len(native["dex_occurrences"]) == 1, "native terminal incomplete")
        occurrence = native["dex_occurrences"][0]
        audit.common.require(occurrence["source"]["content_id"] == "sha256:" + item["sha256"]
                             and occurrence["code"]["source"] == occurrence["source"]
                             and occurrence["raw_code_evidence"]["source"] == occurrence["source"], "source binding differs")
        methods = occurrence["definitions"]["method_definitions"]
        code = occurrence["code"]["items"][0]["data"]
        audit.common.require(len(methods) == 1 and methods[0]["method_idx"] == 0
                             and int(methods[0]["body"]["code_byte_offset"]) == expected["code_off"]
                             and len(code["tries"]) == 1 and len(code["handlers"]) == 1
                             and code["tries"][0]["start_code_unit"] == expected["try_start_pc"]
                             and code["handlers"][0]["catch_all_address_code_units"] == expected["handler_target_pc"],
                             "native method/try binding differs")
        raw_method = occurrence["raw_code_evidence"]["methods"]
        audit.common.require(len(raw_method) == 1 and raw_method[0]["sha256"] == expected["raw_insns_sha256"], "raw hash differs")
        table = audit.common.table((folder / ("a0-" + name) / "stdout.txt").read_bytes(), audit.COLUMNS)
        rows = [{key:None if value == "N" else int(bytes.fromhex(value).decode("ascii")) for key,value in row.items()} for row in table]
        audit.compare_rows(rows, [{column:expected[column] for column in audit.COLUMNS}])
    bad = report["bad_handler"]
    bad_data = (audit.ROOT / "tests/fixtures/owned_try" / bad["fixture"]).read_bytes()
    rebuilt, _ = gen.build(True, True)
    audit.common.require(bad_data == rebuilt and hashlib.sha256(bad_data).hexdigest() == bad["sha256"], "bad fixture differs")
    try:
        audit.oracle(bad_data)
    except RuntimeError as error:
        audit.common.require(str(error) == bad["oracle_error"], "byte oracle error changed")
    else:
        raise RuntimeError("bad handler accepted by byte oracle")
    native_bad = json.loads((folder / "native-bad/stdout.txt").read_text(encoding="utf-8"))
    audit.common.require(exits["native-bad"] == bad["native_exit"] != 0
                         and native_bad["error"] == bad["native_error"]
                         and native_bad["error"]["code"] == "INVALID_INPUT"
                         and native_bad["error"]["details"]["reason"] == "TARGET_NOT_EXECUTABLE_BOUNDARY",
                         "bad native terminal changed")
    audit.common.require(exits["sdk-bad"] == bad["sdk_exit_observed"] != 0
                         and b"Invalid handler catch_all_addr" in (folder / "sdk-bad/stderr.txt").read_bytes(),
                         "SDK bad-handler observation changed")
    audit.common.require(exits["a0-bad"] == bad["a0_exit_observed"] == 0, "A0 bad-handler observation changed")
    a0_bad = audit.common.table((folder / "a0-bad/stdout.txt").read_bytes(), audit.COLUMNS)
    audit.common.require(len(a0_bad) == 1, "A0 bad-handler output row count changed")
    audit.common.require(len(report["negative_controls_rejected"]) == 6, "negative controls incomplete")
    started = datetime.datetime.now(datetime.timezone.utc)
    destination = folder / "readbacks" / started.strftime("%Y%m%dT%H%M%S%fZ")
    destination.mkdir(parents=True, exist_ok=False)
    output = {"status":"passed", "result_sha256":audit.common.digest(result_path),
              "readback_source_sha256":audit.common.digest(Path(__file__)),
              "source_files_checked":len(report["sources"]), "command_records_checked":len(labels),
              "valid_cases":len(report["valid"]), "a0_bad_input_exit":exits["a0-bad"],
              "task_complete_proven":False, "scope":"bounded synthetic structural evidence; no ART/device qualification"}
    payload = (json.dumps(output) + "\n").encode("utf-8")
    (destination / "result.json").write_text(json.dumps(output,indent=2)+"\n",encoding="utf-8")
    (destination / "stdout.txt").write_bytes(payload)
    (destination / "stderr.txt").write_bytes(b"")
    (destination / "command.json").write_text(json.dumps({"argv":[sys.executable,"-O","tests/fixtures/owned_try/readback.py",sys.argv[1]],
        "started_utc":started.isoformat(), "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(), "exit_code":0,
        "stdout_sha256":hashlib.sha256(payload).hexdigest(), "stderr_sha256":hashlib.sha256(b"").hexdigest()},indent=2)+"\n",encoding="utf-8")
    sys.stdout.buffer.write(payload)


if __name__ == "__main__":
    main()
