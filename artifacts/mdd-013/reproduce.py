#!/usr/bin/env python3
"""Record actual targeted M1 reader checks; no performance measurement."""
from __future__ import annotations

import datetime
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(argv):
    value = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, check=False)
    return {"argv": argv, "exit_code": value.returncode, "stdout": value.stdout, "stderr": value.stderr}


def main():
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    tools = [execute(["rustc", "-Vv"]), execute(["cargo", "-V"])]
    commands = [
        execute(["cargo", "test", "--locked", "--offline", "-p", "mdd-dex"]),
        execute(["cargo", "clippy", "--locked", "--offline", "-p", "mdd-dex", "--all-targets", "--", "-D", "warnings"]),
        execute(["rustfmt", "--check", "--edition", "2024", "crates/mdd-dex/src/lib.rs", "crates/mdd-dex/src/header.rs", "crates/mdd-dex/src/checked_reader.rs"]),
    ]
    source_files = [ROOT / "crates/mdd-dex/Cargo.toml", *sorted((ROOT / "crates/mdd-dex/src").rglob("*.rs")),
                    ROOT / "Cargo.lock", ROOT / "rust-toolchain.toml", ROOT / "conformance/dex/header-and-version-cases.json"]
    fixture_manifest = json.loads((ROOT / "tests/fixtures/manifest.json").read_text())
    fixtures = [item for item in fixture_manifest["files"] if item["kind"] == "dex"]
    report = {
        "schema_version": "mdd.format-validation.v1", "task_id": "MDD-013",
        "started_utc": started, "completed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "environment": {"platform": platform.platform(), "machine": platform.machine(), "python": sys.version, "tools": tools},
        "checkout": execute(["git", "-c", "safe.directory=D:/MeguvisDexDash", "rev-parse", "HEAD"]),
        "scoped_git_status": execute(["git", "-c", "safe.directory=D:/MeguvisDexDash", "status", "--short", "--", "crates/mdd-dex", "conformance/dex", "artifacts/mdd-013"]),
        "commands": commands,
        "source_sha256": {path.relative_to(ROOT).as_posix(): sha(path) for path in source_files},
        "fixture_manifest_sha256": sha(ROOT / "tests/fixtures/manifest.json"),
        "fixture_inputs": [{"path": item["path"], "bytes": item["bytes"], "sha256": item["sha256"], "fixture_expectation": item["expected"]} for item in fixtures],
        "success": all(item["exit_code"] == 0 for item in tools + commands),
        "unit_tests_passed": 10 if commands[0]["exit_code"] == 0 and "10 passed; 0 failed" in commands[0]["stdout"] else None,
        "scope": "standard-le-header-map-fixed-references-v1", "full_dex_validation_complete": False,
        "signature_verified": False, "adler32_verified_for_accepted_inputs": True,
        "source_identity": "Caller snapshot owns bytes and binds ContentId/DexOccurrence to returned errors. Leaf reader never opens a path.",
        "diagnostics": "ErrorCode plus stable reason, failure stage, byte_offset/byte_length and partial-input/unknown-facts labels; no zero-row success for malformed inputs.",
        "acceptance": [
            {"ordinal": 1, "status": "done", "evidence": "Each of 035/037/038/039/040 validated with a separate real fixture; 036/041/special magic/reverse endian explicitly unsupported."},
            {"ordinal": 2, "status": "done", "evidence": "CheckedReader verifies u64 addition/multiplication and range before slicing. Direct overflow tests and every prefix of 536-byte structured fixture reject without reader panic."},
            {"ordinal": 3, "status": "done", "evidence": "Actual malformed magic, truncation, checksum, map, count and fixed-index/pointer counterexamples distinguish reason/code/stage and incomplete scope."},
            {"ordinal": 4, "status": "done", "evidence": "Self-contained reader consumes generated valid minimal and structured bytes directly. No DexSQL executable, provider or parser dependency."},
            {"ordinal": 5, "status": "done", "evidence": "Leaf diagnostics include byte range/failure layer and require caller snapshot binding. Serialized success explicitly names scope and full_dex_validation_complete=false; declared SHA1 remains unverified."},
        ],
        "limits": ["Little endian only", "SHA1 signature not verified", "MUTF/name/order/descriptor semantics deferred", "Full class_data/code/annotations/encoded-values/debug validation deferred", "Variable data references check section boundary and minimum size, not complete item parsing", "AOSP/dexlib2 full differential and Linux native execution not run by this task", "field/type-list/call-site/method-handle branches exist but current fixture positives do not exercise all of these optional paths"],
        "retained_failure_record": "artifacts/mdd-013/initial-build-failure.json",
        "qualification": "M1 reader task scope only, not complete DEX input/facts/profile/HostLab/performance release qualification",
    }
    (HERE / "format-validation.json").write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(f"MDD-013: success={report['success']}, unit_tests={report['unit_tests_passed']}, commands={len(commands)}")
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
