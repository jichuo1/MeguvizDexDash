"""Capture scoped local SQL checks; not task/profile qualification."""
import datetime
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "artifacts/mdd-031/local-checks-20261029"
OUT.mkdir(parents=True, exist_ok=True)


def identities():
    paths = [ROOT / "Cargo.lock", ROOT / "Cargo.toml"]
    paths += sorted((ROOT / "crates/mdd-sql").rglob("*.rs"))
    paths.append(ROOT / "crates/mdd-sql/Cargo.toml")
    return {str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def main():
    before = identities()
    checks = [
        ("format", ["cargo", "fmt", "-p", "mdd-sql", "--", "--check"]),
        ("tests", ["cargo", "test", "-p", "mdd-sql", "--locked", "--offline", "--jobs", "1", "--", "--test-threads", "1"]),
        ("clippy", ["cargo", "clippy", "-p", "mdd-sql", "--all-targets", "--locked", "--offline", "--jobs", "1", "--", "-D", "warnings"]),
    ]
    records = []
    for name, command in checks:
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=180)
        (OUT / (name + ".stdout.txt")).write_bytes(result.stdout)
        (OUT / (name + ".stderr.txt")).write_bytes(result.stderr)
        records.append({"name": name, "argv": command, "started_utc": started, "exit_code": result.returncode,
                        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
    after = identities()
    report = {"schema_version": "mdd.local-checks.v1", "scope": "local SQL crate only, not dialect or task qualification",
              "source_and_lock_sha256_before": before, "source_and_lock_sha256_after": after,
              "identities_unchanged": before == after, "checks": records}
    (OUT / "record.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if before != after or any(record["exit_code"] != 0 for record in records):
        raise SystemExit(1)
    print("SQL local scoped checks passed; identities unchanged")


if __name__ == "__main__":
    main()
