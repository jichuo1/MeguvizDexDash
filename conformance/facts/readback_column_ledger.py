#!/usr/bin/env python3
"""Recompute the field inventory and compare every entry without signing a gate."""
import json
import datetime
from pathlib import Path
import subprocess
import sys
import compile_column_ledger as ledger


def main():
    ledger.require(len(sys.argv) == 2, "expected one recorded ledger path")
    base = (ledger.ROOT / "artifacts/mdd-026/column-ledger").resolve()
    folder = (ledger.ROOT / sys.argv[1]).resolve()
    ledger.require(folder.is_relative_to(base) and folder != base, "ledger path outside evidence directory")
    original_path = folder / "column-ledger.json"
    original = json.loads(original_path.read_text(encoding="utf-8"))
    started = datetime.datetime.now(datetime.timezone.utc)
    suffix = started.strftime("%Y%m%dT%H%M%S%fZ")
    append_dir = folder / "readbacks" / suffix
    append_dir.mkdir(parents=True, exist_ok=False)
    run = subprocess.run([sys.executable, "-O", "conformance/facts/compile_column_ledger.py"],
                         cwd=ledger.ROOT, capture_output=True, timeout=90)
    (append_dir / "compiler.stdout.txt").write_bytes(run.stdout)
    (append_dir / "compiler.stderr.txt").write_bytes(run.stderr)
    (append_dir / "compiler-command.json").write_text(json.dumps({
        "argv":[sys.executable, "-O", "conformance/facts/compile_column_ledger.py"],
        "exit_code":run.returncode, "stdout_sha256":ledger.sha(run.stdout), "stderr_sha256":ledger.sha(run.stderr),
        "started_utc":started.isoformat(), "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }, indent=2) + "\n", encoding="utf-8")
    ledger.require(run.returncode == 0, "ledger recomputation failed: " + run.stderr.decode("utf-8", "replace"))
    result = json.loads(run.stdout)
    recomputed_path = ledger.ROOT / result["path"] / "column-ledger.json"
    recomputed = json.loads(recomputed_path.read_text(encoding="utf-8"))
    a, b = dict(original), dict(recomputed)
    a.pop("created_utc")
    b.pop("created_utc")
    ledger.require(a == b, "recomputed field evidence differs")
    ledger.require(len(original["columns"]) == 156 and original["required_relations"] == 17
                   and original["is_task_gate"] is False and original["task_complete_proven"] is False
                   and original["profile_admitted"] is False, "inventory scope/denominator differs")
    ledger.require(all(entry["evidence"] and entry["remaining_boundaries"]
                       and entry["full_field_qualification"] is False for entry in original["columns"]),
                   "missing evidence/boundary or overclaim")
    report = {"status":"passed", "result_sha256":ledger.sha(original_path.read_bytes()),
              "readback_source_sha256":ledger.sha(Path(__file__).read_bytes()),
              "recomputed_result":recomputed_path.relative_to(ledger.ROOT).as_posix(),
              "recomputed_sha256":ledger.sha(recomputed_path.read_bytes()),
              "compiler_stdout_sha256":ledger.sha(run.stdout), "compiler_stderr_sha256":ledger.sha(run.stderr),
              "relations":17, "columns":156, "task_complete_proven":False,
              "scope":"evidence inventory recomputation, not fact/profile qualification"}
    (append_dir / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    stdout = (json.dumps(report) + "\n").encode("utf-8")
    (append_dir / "stdout.txt").write_bytes(stdout)
    (append_dir / "stderr.txt").write_bytes(b"")
    (append_dir / "command.json").write_text(json.dumps({
        "argv":[sys.executable, "-O", "conformance/facts/readback_column_ledger.py", sys.argv[1]],
        "started_utc":started.isoformat(), "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "exit_code":0, "stdout_sha256":ledger.sha(stdout), "stderr_sha256":ledger.sha(b""),
    }, indent=2) + "\n", encoding="utf-8")
    sys.stdout.buffer.write(stdout)


if __name__ == "__main__":
    main()
