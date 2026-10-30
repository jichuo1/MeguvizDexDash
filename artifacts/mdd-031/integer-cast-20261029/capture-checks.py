"""Capture scoped integer conversion checks without overwriting prior evidence."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "checks-20261029"
OUT.mkdir(exist_ok=True)


def identities():
    paths = sorted((ROOT / "crates/mdd-sql").rglob("*.rs")) + [ROOT / "crates/mdd-sql/Cargo.toml", ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
    return {str(path.relative_to(ROOT)).replace("\\", "/"):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def main():
    before = identities()
    commands = [("fmt", ["cargo", "fmt", "-p", "mdd-sql", "--", "--check"]),
                ("test", ["cargo", "test", "-p", "mdd-sql", "--locked", "--offline", "--jobs", "1", "--", "--test-threads", "1"]),
                ("clippy", ["cargo", "clippy", "-p", "mdd-sql", "--all-targets", "--locked", "--offline", "--jobs", "1", "--", "-D", "warnings"])]
    checks = []
    for name, argv in commands:
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=180)
        (OUT / (name + ".stdout.txt")).write_bytes(result.stdout)
        (OUT / (name + ".stderr.txt")).write_bytes(result.stderr)
        checks.append({"name":name,"argv":argv,"started_utc":started,"exit_code":result.returncode,
                       "stdout_sha256":hashlib.sha256(result.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(result.stderr).hexdigest()})
    after = identities()
    report = {"schema_version":"mdd.local-checks.v1","scope":"DexSQL text/blob to integer value conversion; DTO type and SQL affinity not qualified",
              "before":before,"after":after,"identities_unchanged":before==after,"checks":checks,
              "pre_fix_failure":"tool-returned unit error INTEGER_VALUE_REQUIRED; raw test failure not independently persisted; fixed reference observations retained separately"}
    (OUT / "record.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    if before != after or any(check["exit_code"] for check in checks): raise SystemExit(1)
    print("integer CAST scoped checks passed; identities unchanged")


if __name__ == "__main__":
    main()
