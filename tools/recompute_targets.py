#!/usr/bin/env python3
"""Recompute conditional engineering targets from frozen historical observations.

This script never runs, simulates, or benchmarks a MeguvizDexDash implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evidence" / "hostlab_verification.json"
MODEL = ROOT / "evidence" / "measured_phase_model.json"


def compute() -> dict:
    raw = json.loads(SOURCE.read_text(encoding="utf-8"))
    saved = json.loads(MODEL.read_text(encoding="utf-8"))
    by_sha = {item["sha256"]: item for item in raw["samples"]}
    saved_by_sample = {item["sample"]: item for item in saved["samples"]}
    scenarios = [
        ("structural_surface_1_5x", 1.5, 1.5),
        ("structural_surface_2x", 2.0, 2.0),
        ("structural_2x_surface_3x", 2.0, 3.0),
    ]
    result = {
        "record_kind": "conditional_projection_from_historical_observations",
        "engine_implemented": False,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "source_run_url": saved["source_run_url"],
        "formula": "E_new = P + R + O + S / s_S + F / s_F",
        "assumptions": [
            "Only the complete S and F composite phases change.",
            "Identical work and correctness, no additional overhead.",
            "One historical A0 observation per sample; not p95 or a B result.",
            "S/F include engine, transport and consumer work; not pure parsing.",
        ],
        "samples": [],
    }
    for record in raw["rounds"]:
        runs = [r for r in record["runs"] if r.get("implementation") == "dexsql"]
        if len(runs) != 1:
            raise ValueError("Expected exactly one current A0 record per sample")
        run = runs[0]
        native = run["native"]
        if not native["complete"] or not run["audit_complete"]:
            raise ValueError("Historical analysis record is incomplete")
        # The business audit exit code may report findings; do not replace its
        # completeness fields with an invented 'exit 0' requirement here.
        phase = native["phases"]
        e = run["elapsed_ms"] / 1000.0
        p, s, f = (phase[k] / 1000.0 for k in
                   ("prepare_ms", "structural_ms", "surface_ms"))
        n = native["elapsed_ms"] / 1000.0
        r, o = n - p - s - f, e - n
        if min(e, p, s, f, n, r, o) < -1e-8:
            raise ValueError("Negative phase: timing scopes need review")
        sample = by_sha[native["apk_sha256"]]
        expected = saved_by_sample[record["sample"]]
        measured = {"E": e, "P": p, "S": s, "F": f, "R": r, "O": o}
        for name, value in measured.items():
            reference_name = "T" if name == "E" else name
            if not math.isclose(value, expected["measured_seconds"][reference_name],
                                abs_tol=1e-8, rel_tol=1e-10):
                raise ValueError("Frozen source/model discrepancy: " + name)
        targets = []
        expected_scenarios = {x["name"]: x for x in expected["scenarios"]}
        for name, ss, sf in scenarios:
            projected = p + r + o + s / ss + f / sf
            if not math.isclose(projected, expected_scenarios[name]["new_seconds"],
                                abs_tol=1e-8, rel_tol=1e-10):
                raise ValueError("Scenario model discrepancy: " + name)
            targets.append({
                "name": name,
                "assumed_structural_speedup": ss,
                "assumed_surface_speedup": sf,
                "projected_seconds": projected,
                "time_reduction_percent": (1 - projected / e) * 100,
                "whole_task_speedup": e / projected,
            })
        result["samples"].append({
            "version_code": sample["version_code"],
            "input_sha256": native["apk_sha256"],
            "historical_observations": 1,
            "measured_seconds": measured,
            "scenarios": targets,
        })
    if len(result["samples"]) != 2:
        raise ValueError("Expected two frozen historical samples")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print the projection as JSON")
    args = parser.parse_args()
    result = compute()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("CONDITIONAL TARGETS ONLY — MeguvizDexDash has not been implemented or measured.")
        print("version | A0 seconds | S target | F target | projected seconds | time reduction | speedup")
        for sample in result["samples"]:
            for target in sample["scenarios"]:
                print(f"{sample['version_code']} | {sample['measured_seconds']['E']:.6f} | "
                      f"{target['assumed_structural_speedup']:.1f}x | "
                      f"{target['assumed_surface_speedup']:.1f}x | "
                      f"{target['projected_seconds']:.6f} | "
                      f"{target['time_reduction_percent']:.2f}% | "
                      f"{target['whole_task_speedup']:.4f}x")
        print("Verified against the frozen raw observations and phase model; no engine benchmark ran.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
