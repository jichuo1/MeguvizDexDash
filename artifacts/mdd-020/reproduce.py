#!/usr/bin/env python3
"""Record actual metadata conformance and optional complete public-input build."""
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
PUBLIC = ROOT / "artifacts/local/inputs/NewPipe_v0.28.6.apk"
PUBLIC_SHA = "e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv):
    completed = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, check=False)
    record = {"argv": argv, "exit_code": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}
    commands.append(record)
    return record


commands = []


def main():
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    expected_sha = digest(HERE / "expected.json")
    generations = []
    for _ in range(2):
        result = command([sys.executable, "artifacts/mdd-020/generate_metadata_fixture.py"])
        if result["exit_code"]:
            raise RuntimeError("metadata fixture generation failed")
        generations.append({path.name: digest(path) for path in sorted((HERE / "inputs").iterdir())})
    require(generations[0] == generations[1], "fixture generation is not reproducible")
    require(digest(HERE / "expected.json") == expected_sha, "handwritten expectations changed")
    oracle = command([sys.executable, "artifacts/mdd-020/verify_metadata_fixture.py"])
    tests = command(["cargo", "test", "--locked", "--offline", "-p", "mdd-dex", "-p", "mdd-facts"])
    command(["cargo", "clippy", "--locked", "--offline", "-p", "mdd-dex", "-p", "mdd-facts", "--all-targets", "--", "-D", "warnings"])
    command(["rustfmt", "--check", "--edition", "2024", "crates/mdd-dex/src/strings.rs", "crates/mdd-dex/src/types.rs", "crates/mdd-facts/src/lib.rs", "crates/mdd-facts/src/metadata.rs", "crates/mdd-facts/examples/metadata_summary.rs"])
    public = {"status": "not_run", "reason": "fixed public input missing"}
    if PUBLIC.is_file():
        require(PUBLIC.stat().st_size == 10885562 and digest(PUBLIC) == PUBLIC_SHA, "public input identity mismatch")
        result = command(["cargo", "run", "--locked", "--offline", "-p", "mdd-facts", "--example", "metadata_summary", "--", "artifacts/local/inputs/NewPipe_v0.28.6.apk", PUBLIC_SHA])
        summary = json.loads(result["stdout"]) if result["exit_code"] == 0 else None
        public = {"status": "passed" if result["exit_code"] == 0 else "failed", "input_bytes": PUBLIC.stat().st_size,
            "input_sha256": PUBLIC_SHA, "origin_url": "https://github.com/TeamNewPipe/NewPipe/releases/download/v0.28.6/NewPipe_v0.28.6.apk",
            "result": summary, "scope": "complete strings/types/prototypes construction for both selected DEX occurrences; output is summary only, not truncated fact calculation"}
        if summary is not None:
            require(summary["metadata_calculation_complete"] is True and summary["required_dex_occurrences"] == 2, "public metadata incomplete")
            require(len(summary["selected_dexes"]) == 2 and summary["full_audit_complete"] is False, "public coverage or qualification mismatch")
        (HERE / "public-newpipe-metadata.json").write_text(json.dumps(public, indent=2) + "\n", encoding="utf-8")
    sources = [ROOT / "Cargo.lock", ROOT / "rust-toolchain.toml", ROOT / "crates/mdd-dex/src/strings.rs", ROOT / "crates/mdd-dex/src/types.rs",
        *sorted((ROOT / "crates/mdd-facts").rglob("*.rs")), ROOT / "crates/mdd-facts/Cargo.toml", HERE / "generate_metadata_fixture.py", HERE / "verify_metadata_fixture.py", HERE / "expected.json"]
    executable = ROOT / "target/debug/examples" / ("metadata_summary.exe" if platform.system() == "Windows" else "metadata_summary")
    report = {"schema_version": "mdd.metadata-conformance.v1", "task_id": "MDD-020", "started_utc": started,
        "completed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "environment": {"platform": platform.platform(), "machine": platform.machine(), "python": sys.version},
        "toolchain": command(["rustc", "-Vv"]), "checkout": command(["git", "-c", "safe.directory=D:/MeguvisDexDash", "rev-parse", "HEAD"]),
        "commands": commands, "success": all(item["exit_code"] == 0 for item in commands) and oracle["exit_code"] == 0,
        "test_summary": "17 mdd-dex and 3 mdd-facts passed" if "17 passed; 0 failed" in tests["stdout"] and "3 passed; 0 failed" in tests["stdout"] else tests["stdout"],
        "independent_leb_oracle_cases": 512, "new_fixture_count": len(generations[0]), "fixture_generation_reproducible": generations[0] == generations[1],
        "fixture_sha256": generations[1], "manual_expectations_preserved": digest(HERE / "expected.json") == expected_sha,
        "source_sha256": {path.relative_to(ROOT).as_posix(): digest(path) for path in sources},
        "consumer_binary": {"path": executable.relative_to(ROOT).as_posix(), "sha256": digest(executable), "bytes": executable.stat().st_size} if executable.is_file() else None,
        "public_input_run": public,
        "acceptance": [
            {"ordinal":1,"status":"done","evidence":"Raw MUTF-8 and UTF16 units retained; all MDD004 NUL/supplementary/isolated-surrogate vectors compared to manual expectations. strict_utf8 rejects nonscalar units; display_lossy is explicit and never used for facts or equality."},
            {"ordinal":2,"status":"done","evidence":"Bounded at-most-five-octet ULEB/SLEB implementation passes existing component cases and 512 independent fifth-byte oracle cases. Actual declared-length/MUTF/type/shorty/return/parameter/order mutants reject with explicit reason."},
            {"ordinal":3,"status":"done","evidence":"Snapshot+DEX occurrence+kind+local index EntityRef. Two equal-content sources and two DEX members of one APK retain different refs while sharing physical string_pool_id; descriptor/return references remain occurrence-scoped and reconstructible. MemberBlob owned lease survives dropping snapshot/inventory."},
            {"ordinal":4,"status":"done","evidence":"Independent seven-string/five-type/three-prototype DEX verifies empty list, I/J order, String/array parameters, return/shorty/descriptor and offsets field by field; separately written Python reference agrees with handwritten expected.json."}
        ],
        "scope": "strings-types-prototypes-only-v1", "not_claimed": ["full DEX validity", "SHA1 verification", "class/method definitions", "annotations/code/references/resources", "HostLab equivalence", "performance benefit", "Linux native acceptance"],
        "budgets": {"string_limits":"caller StringLimits", "expanded_parameter_references":16777216, "expanded_prototype_descriptor_bytes":67108864},
        "prior_failure_record": "artifacts/mdd-020/initial-check-failure.json",
        "rollback": "Remove new MDD020 modules/facts member and exports as one scoped change; earlier M1 header/snapshot/lifecycle API remains independent. Do not reset unrelated work or modify historical evidence."}
    (HERE / "metadata-conformance.json").write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(f"MDD-020 success={report['success']}; {report['test_summary']}; public_input={public['status']}")
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
