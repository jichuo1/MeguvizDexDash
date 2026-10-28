#!/usr/bin/env python3
"""Recompute private resource-only comparison; save summaries and hashes only."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    require(len(sys.argv) == 2, "expected command record")
    record_path = (ROOT / sys.argv[1]).resolve(strict=True)
    allowed = (ROOT / "artifacts/integration/20261028").resolve()
    require(record_path.is_relative_to(allowed), "record path outside integration evidence")
    command = json.loads(record_path.read_bytes())
    require(command["status"] == "passed" and len(command["runs"]) == 2
            and all(run["exit_code"] == 0 for run in command["runs"]), "original command not successful")
    for run in command["runs"]:
        require(sha((ROOT / run["script"]).read_bytes()) == run["script_sha256"], "original verifier source changed")
    original_path = (ROOT / command["comparison_receipt"]).resolve(strict=True)
    require(original_path.is_relative_to(allowed), "comparison path outside integration evidence")
    original_bytes = original_path.read_bytes()
    require(sha(original_bytes) == command["comparison_sha256"], "original comparison hash changed")
    original = json.loads(original_bytes)
    require(original["status"] == "passed-resource-byte-equivalence-only"
            and not original["method_fingerprints_compared"] and not original["performance_qualified"]
            and not original["full_hostlab_audit_equivalent"], "original scope overclaimed")
    started = datetime.now(timezone.utc)
    proc = subprocess.run([sys.executable,"-O","conformance/resources/compare_private_resource_evidence.py"],
                          cwd=ROOT,capture_output=True,timeout=120)
    output = allowed / ("private-resource-readback-" + started.strftime("%Y%m%dT%H%M%S%fZ") + ".json")
    report = {"schema_version":"mdd.private-resource-readback.v1", "status":"running",
              "started_utc":started.isoformat(), "original_comparison_sha256":sha(original_bytes),
              "original_command_sha256":sha(record_path.read_bytes()),
              "recompute_exit_code":proc.returncode, "recompute_stdout_sha256":sha(proc.stdout),
              "recompute_stderr_sha256":sha(proc.stderr), "method_fingerprints_compared":False,
              "performance_qualified":False, "full_hostlab_audit_equivalent":False}
    try:
        require(proc.returncode == 0, "recompute failed")
        returned = json.loads(proc.stdout)
        new_path = (ROOT / returned["receipt"]).resolve(strict=True)
        require(new_path.is_relative_to(allowed), "recomputed receipt path outside integration evidence")
        new = json.loads(new_path.read_bytes())
        a,b = dict(original),dict(new)
        a.pop("created_utc")
        b.pop("created_utc")
        require(a == b, "resource comparison changed on recomputation")
        report.update(status="passed", recomputed_comparison_sha256=sha(new_path.read_bytes()),
                      sample_count=len(new["results"]), resource_counts=[x["resource_entries"] for x in new["results"]],
                      verifier_source_sha256=sha(Path(__file__).read_bytes()))
    except Exception as error:
        report.update(status="failed", failure_type=type(error).__name__)
        output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8",newline="\n")
        raise
    output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps({"receipt":output.relative_to(ROOT).as_posix(), "status":"passed",
                      "resource_counts":report["resource_counts"], "method_fingerprints_compared":False}))


if __name__ == "__main__":
    main()
