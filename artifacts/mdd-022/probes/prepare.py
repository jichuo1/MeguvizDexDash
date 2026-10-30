#!/usr/bin/env python3
"""Reproduce preflight fixtures/oracles while retaining original A0 observations."""
from __future__ import annotations

import datetime
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
FIXTURES = ROOT / "tests/fixtures/annotations"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    commands, generations = [], []
    expected_sha = digest(FIXTURES / "expected.json")

    def command(arguments):
        completed = subprocess.run([sys.executable, *arguments], cwd=ROOT, capture_output=True, text=True, check=False)
        commands.append({"argv":[sys.executable,*arguments],"exit_code":completed.returncode,"stdout":completed.stdout,"stderr":completed.stderr})
        require(completed.returncode == 0,"preflight command failed: "+" ".join(arguments))

    for _ in range(2):
        command(["tests/fixtures/annotations/generate.py"])
        generations.append({path.name:digest(path) for path in sorted((FIXTURES/"generated").iterdir())})
    require(generations[0] == generations[1],"fixture generation is not deterministic")
    require(digest(FIXTURES/"expected.json") == expected_sha,"handwritten expectation changed")
    command(["tests/fixtures/annotations/oracle.py"])
    command(["-O","tests/fixtures/annotations/oracle.py"])
    command(["artifacts/mdd-022/probes/compare_oracle.py"])
    command(["-O","artifacts/mdd-022/probes/compare_oracle.py"])
    reference = json.loads((HERE/"reference-results.json").read_text())
    oracle = json.loads((FIXTURES/"oracle-results.json").read_text())
    comparison = json.loads((HERE/"oracle-comparison.json").read_text())
    require(reference["success"] and oracle["success"] and comparison["success"],"failed reference/oracle/comparison")
    sources = [FIXTURES/"generate.py", FIXTURES/"oracle.py", FIXTURES/"expected.json", HERE/"probe_reference.py", HERE/"compare_oracle.py", Path(__file__).resolve()]
    report = {"schema_version":"mdd.annotation-preparation.v1","task_id":"MDD-022","time_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "phase":"independent-fixture-and-compatibility-oracle-preflight","production_annotation_implementation_started":False,"task_done":False,
        "commands":commands,"success":True,"fixture_generation_reproducible":True,"fixture_sha256":generations[1],
        "manual_expectation_sha256":expected_sha,"fixture_checks":len(oracle["fixture_checks"]),"component_checks":len(oracle["component_checks"]),
        "reference_observation":"Existing immutable verified A0 observation; not rerun or newly presented as an engine trial by this script.",
        "reference_result_sha256":digest(HERE/"reference-results.json"),"reference_binary":reference["reference"],"reference_input":reference["input"],
        "six_complete_relation_comparisons":comparison["comparisons"],"source_sha256":{path.relative_to(ROOT).as_posix():digest(path) for path in sources},
        "production_dependency":"MDD-021 root acceptance still required before AnnotationFacts implementation and MDD-022 task completion.",
        "limits":["Only one synthetic positive annotated DEX and explicit invalid/component vectors", "A0 Windows0.1.0 reference only", "No private HostLab audit", "No performance trial", "No production annotation task qualification"],
        "retained_failures":"artifacts/mdd-022/probes/initial-preflight-failures.json"}
    (HERE/"preparation-summary.json").write_text(json.dumps(report,indent=2,allow_nan=False)+"\n",encoding="utf-8")
    print(f"annotation preflight success: fixtures={report['fixture_checks']}, components={report['component_checks']}, complete_relations={len(comparison['comparisons'])}; task_done=false")


if __name__ == "__main__":
    main()
