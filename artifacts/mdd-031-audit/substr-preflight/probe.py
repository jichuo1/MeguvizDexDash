"""Observe fixed A0/A1 substr behavior on a public synthetic DEX, not qualification."""
from pathlib import Path
import asyncio
import datetime
import importlib.metadata
import importlib.util
import json
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "artifacts/mdd-033/preflight/probe_temp_policy.py"
spec = importlib.util.spec_from_file_location("mdd_reference_helper", HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

helper.CASES = [
    ("positive", ["SELECT substr('abcdef',2,3) AS value"]),
    ("negative_start", ["SELECT substr('abcdef',-3,2) AS value"]),
    ("negative_length", ["SELECT substr('abcdef',4,-2) AS value"]),
    ("nul", ["SELECT substr('A\x00B',2,2) AS value"]),
    ("supplementary", ["SELECT substr('😀A',1,1) AS value"]),
    ("null", ["SELECT substr(NULL,1,1) AS value"]),
    ("bytes", ["SELECT substr(X'414243',2,1) AS value"]),
    ("substring", ["SELECT substring('abcdef',2,3) AS value"]),
]


async def main():
    helper.require(importlib.metadata.version("mcp") == "2.2.0", "fixed MCP version required")
    helper.require(helper.FIXTURE.stat().st_size == 660 and helper.digest(helper.FIXTURE) == helper.FIXTURE_SHA, "fixture mismatch")
    plan = json.loads((ROOT / "benchmarks/baseline-manifest.json").read_text(encoding="utf-8"))
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = Path(__file__).resolve().parent / stamp
    directory.mkdir(exist_ok=False)
    records = []
    for name in ("A0", "A1"):
        variant = next(item for item in plan["variants"] if item["id"] == name)
        result = await helper.probe(variant, directory)
        records.append({"variant": name, "cases": len(result["cases"]), "observations_sha256": helper.digest(directory / (name + ".observations.json"))})
    helper.require(helper.digest(helper.FIXTURE) == helper.FIXTURE_SHA, "fixture changed")
    summary = {"scope": "fixed DexSQL substr observations, not legacy SQLite qualification", "profiles_admitted": False, "formal_performance_measurement": False, "private_input_parsed": False, "driver_sha256": helper.digest(Path(__file__).resolve()), "helper_sha256": helper.digest(HELPER), "fixture_sha256": helper.FIXTURE_SHA, "records": records}
    helper.dump(directory / "summary.json", summary)
    print(json.dumps({"directory": str(directory), "records": records}))


if __name__ == "__main__":
    asyncio.run(main())
