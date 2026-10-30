#!/usr/bin/env python3
"""Append-only, full recomputation and negative controls for the v2 field ledger."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import compile_column_ledger_v2 as audit


def run_recorded(directory, label, args):
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    proc = subprocess.run([sys.executable, "-O", *args], cwd=audit.ROOT, capture_output=True, timeout=90)
    (directory / (label + ".stdout.txt")).write_bytes(proc.stdout)
    (directory / (label + ".stderr.txt")).write_bytes(proc.stderr)
    (directory / (label + ".record.json")).write_text(json.dumps({"argv":[sys.executable,"-O",*args],
        "started_utc":started, "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "exit_code":proc.returncode, "stdout_sha256":hashlib.sha256(proc.stdout).hexdigest(),
        "stderr_sha256":hashlib.sha256(proc.stderr).hexdigest()},indent=2)+"\n",encoding="utf-8")
    audit.base.require(proc.returncode == 0, label + " failed; original output retained")
    return proc.stdout


def main():
    audit.base.require(len(sys.argv) == 2, "expected one v2 ledger path")
    base = (audit.ROOT / "artifacts/mdd-026/column-ledger-v2").resolve()
    folder = (audit.ROOT / sys.argv[1]).resolve()
    audit.base.require(folder.is_relative_to(base) and folder != base, "run path outside v2 ledger")
    result_path = folder / "column-ledger.json"
    original = json.loads(result_path.read_text(encoding="utf-8"))
    started = datetime.datetime.now(datetime.timezone.utc)
    append = folder / "readbacks" / started.strftime("%Y%m%dT%H%M%S%fZ")
    append.mkdir(parents=True, exist_ok=False)
    stdout = run_recorded(append, "recompute", ["conformance/facts/compile_column_ledger_v2.py"])
    recomputed_dir = audit.ROOT / json.loads(stdout)["path"]
    recomputed = json.loads((recomputed_dir / "column-ledger.json").read_text(encoding="utf-8"))
    a, b = dict(original), dict(recomputed)
    for value in [a,b]:
        value.pop("created_utc")
        value.pop("base_recomputation")
    audit.base.require(a == b, "v2 full recomputation differs")
    audit.base.require(original["required_relations"] == 17 and original["required_columns"] == len(original["columns"]) == 156
                       and original["unassembled_projection_columns"] == 69, "frozen denominator differs")
    audit.base.require(not original["is_task_gate"] and not original["task_complete_proven"] and not original["profile_admitted"]
                       and all(x["full_field_qualification"] is False for x in original["columns"]), "qualification overclaimed")
    code = [x for x in original["columns"] if x["relation"] == "code_items"]
    audit.base.require(len(code) == 12 and all(any(e["slice"] == "owned_try" for e in x["evidence"]) for x in code),
                       "owned-try field links incomplete")
    test_stdout = run_recorded(append, "negative-controls", ["conformance/facts/test_column_ledger_v2.py"])
    audit.base.require(b"4 malformed-handler evidence mutations rejected" in test_stdout, "negative controls incomplete")
    report = {"status":"passed", "result_sha256":audit.base.sha(result_path.read_bytes()),
              "readback_source_sha256":audit.base.sha(Path(__file__).read_bytes()),
              "recomputed_result":(recomputed_dir / "column-ledger.json").relative_to(audit.ROOT).as_posix(),
              "recomputed_sha256":audit.base.sha((recomputed_dir / "column-ledger.json").read_bytes()),
              "relations":17, "columns":156, "owned_try_columns":12, "negative_controls":4,
              "task_complete_proven":False, "scope":"append-only evidence inventory readback, not qualification"}
    payload = (json.dumps(report) + "\n").encode("utf-8")
    (append / "result.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    (append / "stdout.txt").write_bytes(payload)
    (append / "stderr.txt").write_bytes(b"")
    (append / "command.json").write_text(json.dumps({"argv":[sys.executable,"-O","conformance/facts/readback_column_ledger_v2.py",sys.argv[1]],
        "started_utc":started.isoformat(), "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "exit_code":0, "stdout_sha256":hashlib.sha256(payload).hexdigest(), "stderr_sha256":hashlib.sha256(b"").hexdigest()},
        indent=2)+"\n",encoding="utf-8")
    sys.stdout.buffer.write(payload)


if __name__ == "__main__":
    main()
