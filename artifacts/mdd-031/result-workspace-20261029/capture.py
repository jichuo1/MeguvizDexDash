"""Scoped SQL result budget evidence, not complete SQLite memory accounting."""
import datetime
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent


def identities():
    paths = sorted((ROOT / "crates/mdd-sql").rglob("*.rs"))
    paths += [ROOT / "crates/mdd-sql/Cargo.toml", ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
    return {str(path.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def main():
    before = identities()
    commands = [
        ("fmt", ["cargo", "fmt", "-p", "mdd-sql", "--", "--check"]),
        ("test", ["cargo", "test", "-p", "mdd-sql", "--locked", "--offline", "--jobs", "1", "--", "--test-threads", "1"]),
        ("clippy", ["cargo", "clippy", "-p", "mdd-sql", "--all-targets", "--locked", "--offline", "--jobs", "1", "--", "-D", "warnings"]),
    ]
    checks = []
    for name, command in commands:
        start = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=180)
        for kind, data in [("stdout", result.stdout), ("stderr", result.stderr)]:
            (OUT / f"{name}.{kind}.txt").write_bytes(data)
        checks.append({"name": name, "argv": command, "started_utc": start, "exit_code": result.returncode,
                       "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
    after = identities()
    report = {"schema_version": "mdd.local-checks.v1", "scope": "SQL result-owned logical workspace only; SQLite internal allocations and transport copies are not accounted",
              "pre_fix_observation": {"basis": "tool-returned output; raw output and failure-source hash were not separately persisted", "exit_code": 1,
                                      "result": "one-byte result workspace budget returned fourteen rows with calculation_complete=true"},
              "intermediate_test_failure": {"basis": "tool-returned output; raw output and failure-source hash were not separately persisted", "exit_code": 1,
                                            "result": "test indexed absent zero-usage map entry; corrected assertion uses get with zero default"},
              "source_and_lock_sha256_before": before, "source_and_lock_sha256_after": after,
              "identities_unchanged": before == after, "checks": checks}
    (OUT / "record.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if before != after or any(check["exit_code"] for check in checks):
        raise SystemExit(1)
    print("result workspace scoped checks passed; identities unchanged")


if __name__ == "__main__":
    main()
