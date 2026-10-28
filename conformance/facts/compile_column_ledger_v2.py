#!/usr/bin/env python3
"""Append owned-try evidence to a freshly recomputed non-qualifying field ledger."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import compile_column_ledger as base

ROOT = base.ROOT
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT = ROOT / "artifacts/mdd-026/column-ledger-v2" / STAMP
OWNED = "artifacts/mdd-026/owned-try-audit/20261028T171328758066Z"
READBACK = OWNED + "/readbacks/20261028T171444308981Z"
GENERATION = "artifacts/mdd-026/owned-try-audit/20261028T171201209773Z/generate"


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def verify_command(folder, expected_exit):
    record = load(folder + "/record.json")
    base.require(record["exit_code"] == expected_exit, "owned-try command terminal mismatch: " + folder)
    base.verify_receipt(record, (ROOT / folder / "stdout.txt").read_bytes(),
                        (ROOT / folder / "stderr.txt").read_bytes(), expected_exit != 0)
    return base.identity(folder + "/record.json")


def verify_append_readback(result):
    readback = load(READBACK + "/result.json")
    command = load(READBACK + "/command.json")
    base.require(readback["status"] == "passed" and not readback["task_complete_proven"]
                 and readback["result_sha256"] == base.identity(OWNED + "/result.json")["sha256"],
                 "owned-try readback/result identity mismatch")
    base.verify_receipt(command, (ROOT / READBACK / "stdout.txt").read_bytes(),
                        (ROOT / READBACK / "stderr.txt").read_bytes(), False)
    base.require(readback["valid_cases"] == len(result["valid"]) == 2 and readback["command_records_checked"] == 11,
                 "owned-try readback scope differs")
    return readback


def verify_bad_terminals(result, native, sdk_stderr, a0_stdout):
    bad = result["bad_handler"]
    base.require(bad["native_exit"] != 0 and bad["sdk_exit_observed"] != 0 and bad["a0_exit_observed"] == 0,
                 "owned-try negative exit observations differ")
    base.require(native["operation_status"] == "error" and native["error"] == bad["native_error"]
                 and native["error"]["code"] == "INVALID_INPUT"
                 and native["error"]["details"]["reason"] == "TARGET_NOT_EXECUTABLE_BOUNDARY",
                 "owned-try native error was changed or wrapped")
    base.require(b"Invalid handler catch_all_addr" in sdk_stderr and a0_stdout.count(b"| 30 ") >= 1,
                 "owned-try SDK/A0 negative outputs differ")


def inspect_owned():
    result = load(OWNED + "/result.json")
    base.require(not result["task_complete_proven"] and not result["profile_admitted"], "owned-try scope overclaimed")
    verify_append_readback(result)
    base.require(len(result["negative_controls_rejected"]) == 6, "owned-try mutation controls incomplete")
    records = [verify_command(GENERATION, 0)]
    for label in ["build", "compile", "sdk-owned-try-even.dex", "native-owned-try-even.dex", "a0-owned-try-even.dex",
                  "sdk-owned-try-odd.dex", "native-owned-try-odd.dex", "a0-owned-try-odd.dex"]:
        records.append(verify_command(OWNED + "/" + label, 0))
    bad = result["bad_handler"]
    for label, code in [("native-bad",bad["native_exit"]), ("sdk-bad",bad["sdk_exit_observed"]),
                        ("a0-bad",bad["a0_exit_observed"])]:
        records.append(verify_command(OWNED + "/" + label, code))
    verify_bad_terminals(result, load(OWNED + "/native-bad/stdout.txt"),
                         (ROOT / OWNED / "sdk-bad/stderr.txt").read_bytes(),
                         (ROOT / OWNED / "a0-bad/stdout.txt").read_bytes())
    manifest_path = "tests/fixtures/owned_try/manifest.json"
    manifest = load(manifest_path)
    fixtures = {Path(item["path"]).name:item for item in manifest["files"]}
    base.require(set(fixtures) == {"owned-try-even.dex", "owned-try-odd.dex", "owned-try-bad-handler.dex"},
                 "owned-try fixture denominator differs")
    for name, item in fixtures.items():
        path = "tests/fixtures/owned_try/" + item["path"]
        base.require(base.identity(path)["sha256"] == item["sha256"], "owned-try fixture identity differs: " + name)
    path = ROOT / "tests/fixtures/owned_try/verify.py"
    base.require(base.sha(path.read_bytes()) == result["sources"]["tests/fixtures/owned_try/verify.py"],
                 "independent byte oracle source changed")
    spec = importlib.util.spec_from_file_location("mdd_owned_try_v2_oracle", path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    for item in result["valid"]:
        name = item["fixture"]
        raw = (ROOT / "tests/fixtures/owned_try" / fixtures[name]["path"]).read_bytes()
        expected = verifier.oracle(raw)
        base.require(expected == item["byte_oracle"] and expected["tries_off"] is not None
                     and expected["handlers_off"] is not None, "owned-try byte oracle differs")
        table = verifier.common.table((ROOT / OWNED / ("a0-" + name) / "stdout.txt").read_bytes(), verifier.COLUMNS)
        rows = [{key:None if value == "N" else int(bytes.fromhex(value).decode("ascii")) for key,value in row.items()}
                for row in table]
        verifier.compare_rows(rows, [{column:expected[column] for column in verifier.COLUMNS}])
        native = load(OWNED + "/native-" + name + "/stdout.txt")
        base.require(native["probe_complete"] and native["operation_status"] == "ok"
                     and len(native["dex_occurrences"]) == 1, "owned-try native incomplete")
        occurrence = native["dex_occurrences"][0]
        base.require(occurrence["source"]["content_id"] == "sha256:" + item["sha256"]
                     and occurrence["source"] == occurrence["code"]["source"]
                     and len(occurrence["definitions"]["method_definitions"]) == 1
                     and int(occurrence["definitions"]["method_definitions"][0]["body"]["code_byte_offset"]) == expected["code_off"]
                     and occurrence["raw_code_evidence"]["methods"][0]["sha256"] == expected["raw_insns_sha256"],
                     "owned-try source/owner/raw identity differs")
    base.require({item["byte_oracle"]["padding_bytes"] for item in result["valid"]} == {0,2},
                 "even/odd alignment boundaries missing")
    drift = []
    for path, expected in result["sources"].items():
        full = ROOT / path
        actual = base.sha(full.read_bytes()) if full.is_file() else None
        if actual != expected:
            drift.append({"path":path, "tested_sha256":expected, "current_sha256":actual})
    return {"result":base.identity(OWNED + "/result.json"), "readback":base.identity(READBACK + "/result.json"),
            "readback_command":base.identity(READBACK + "/command.json"), "verified_process_records":records,
            "fixture_manifest":base.identity(manifest_path), "current_source_drift":drift,
            "a0_bad_handler_exit_observed":bad["a0_exit_observed"],
            "native_bad_handler_code":bad["native_error"]["code"],
            "scope":"two synthetic owned method bodies; even/odd alignment; SDK is format observation only",
            "limits":result["limits"]}


def main():
    OUT.mkdir(parents=True, exist_ok=False)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    proc = subprocess.run([sys.executable, "-O", "conformance/facts/compile_column_ledger.py"],
                          cwd=ROOT, capture_output=True, timeout=90)
    (OUT / "base-compiler.stdout.txt").write_bytes(proc.stdout)
    (OUT / "base-compiler.stderr.txt").write_bytes(proc.stderr)
    (OUT / "base-compiler.record.json").write_text(json.dumps({
        "argv":[sys.executable,"-O","conformance/facts/compile_column_ledger.py"], "started_utc":started,
        "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(), "exit_code":proc.returncode,
        "stdout_sha256":base.sha(proc.stdout), "stderr_sha256":base.sha(proc.stderr)}, indent=2) + "\n", encoding="utf-8")
    base.require(proc.returncode == 0, "base field ledger recomputation failed; output retained")
    base_summary = json.loads(proc.stdout)
    base_path = Path(base_summary["path"]) / "column-ledger.json"
    report = load(base_path.as_posix())
    base.require(report["required_relations"] == 17 and report["required_columns"] == 156
                 and not report["task_complete_proven"] and not report["profile_admitted"], "base scope differs")
    evidence = inspect_owned()
    report["schema_version"] = "mdd.scoped-field-evidence-ledger.v2"
    report["created_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report["base_recomputation"] = base.identity(base_path.as_posix())
    report["slices"]["owned_try"] = evidence
    updated = []
    for column in report["columns"]:
        if column["relation"] != "code_items":
            continue
        column["evidence"].append({"slice":"owned_try", "type":"owned_method_even_odd_byte_oracle_native_and_A0"})
        if column["name"] in {"tries_off", "handlers_off"}:
            old = "Non-NULL offsets were observed in an unowned physical code item, not an A0 method-owned row."
            base.require(old in column["remaining_boundaries"], "old try boundary missing")
            column["remaining_boundaries"].remove(old)
            column["remaining_boundaries"].append(
                "Non-NULL offsets now observed in two synthetic method-owned items including even/odd padding; other handlers, real corpus and production row assembly remain unverified.")
        base.require(column["full_field_qualification"] is False, "field qualification overclaimed")
        updated.append(column["name"])
    base.require(len(updated) == 12 and report["unassembled_projection_columns"] == 69,
                 "code field/unassembled denominator changed")
    base.require(all(x["full_field_qualification"] is False for x in report["columns"]), "field was promoted")
    report["global_remaining"].append(
        "The malformed owned handler is INVALID_INPUT in native and rejected by SDK; A0 returned a row, which does not excuse the true error.")
    report["is_task_gate"] = False
    report["task_complete_proven"] = False
    report["profile_admitted"] = False
    (OUT / "column-ledger.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps({"path":str(OUT.relative_to(ROOT)), "relations":17, "columns":156,
                      "owned_try_fields_updated":len(updated), "unassembled_columns":69,
                      "source_drift_count":len(evidence["current_source_drift"]), "task_complete_proven":False}))


if __name__ == "__main__":
    main()
