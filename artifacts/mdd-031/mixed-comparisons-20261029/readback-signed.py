"""Independently recheck signed literals and explicit legacy arithmetic gap."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BEFORE = HERE / "runs/20261028T171200202170Z"
AFTER = HERE / "runs/20261028T171954497119Z"
spec = importlib.util.spec_from_file_location("mdd_mixed_readback", HERE / "readback.py")
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)


def verify_extra(after):
    cases = {case["id"]:case for case in after["cases"]}
    signed = cases["signed_literal"]
    prior.require(signed["sqlite_value"] == 1, "signed SQLite value")
    for engine in ("A0", "A1"):
        prior.require(signed["engines"][engine]["exit_code"] == 0 and signed["engines"][engine]["display_value"] == "1", "signed reference value")
    for dialect in ("bridge-native", "bridge-010", "bridge-011"):
        item = signed["engines"][dialect]
        prior.require(item["exit_code"] == 0 and item["result"]["result"]["rows"][0][0] == {"type":"i64","value":"1"}, "signed candidate value")
    arithmetic = cases["legacy_text_arithmetic"]
    prior.require(arithmetic["sqlite_value"] == 1, "arithmetic SQLite value")
    for engine in ("A0", "A1"):
        prior.require(arithmetic["engines"][engine]["exit_code"] == 0 and arithmetic["engines"][engine]["display_value"] == "1", "legacy arithmetic value")
    for dialect, code in (("bridge-native", "INVALID_ARGUMENT"), ("bridge-010", "UNSUPPORTED_QUERY"), ("bridge-011", "UNSUPPORTED_QUERY")):
        item = arithmetic["engines"][dialect]
        prior.require(item["exit_code"] != 0 and item["result"]["error"]["code"] == code, "arithmetic gap classification")


def main():
    before = json.loads((BEFORE / "observations.json").read_text(encoding="utf-8"))
    after = json.loads((AFTER / "observations.json").read_text(encoding="utf-8"))
    identity = json.loads((AFTER / "wrapper-identity.json").read_text(encoding="utf-8"))
    prior.require(prior.digest((HERE / "observe.py").read_bytes()) == identity["observer_sha256"], "observer changed")
    prior.require(prior.digest((HERE / "observe-signed.py").read_bytes()) == identity["wrapper_sha256"], "wrapper changed")
    for path, sha in after["source_sha256"].items():
        prior.require(prior.digest((ROOT / path).read_bytes()) == sha, "source mismatch " + path)
    fixture = ROOT / "tests/fixtures/references/generated/classic-035.dex"
    prior.require(prior.digest(fixture.read_bytes()) == before["fixture_sha256"] == after["fixture_sha256"], "fixture mismatch")
    prior.verify_run(BEFORE, before)
    prior.verify_run(AFTER, after)
    baseline = copy.deepcopy(after)
    baseline["cases"] = [case for case in baseline["cases"] if case["id"] not in {"signed_literal", "legacy_text_arithmetic"}]
    prior.check_results(before, baseline)
    verify_extra(after)
    negatives = []
    for name in ("signed_wrong", "legacy_false_success"):
        changed = copy.deepcopy(after)
        cases = {case["id"]:case for case in changed["cases"]}
        if name == "signed_wrong": cases["signed_literal"]["engines"]["bridge-010"]["result"]["result"]["rows"][0][0]["value"] = "0"
        else: cases["legacy_text_arithmetic"]["engines"]["bridge-010"]["exit_code"] = 0
        try:
            verify_extra(changed)
        except RuntimeError:
            negatives.append(name)
        else:
            raise RuntimeError("negative control accepted: " + name)
    report = {"schema_version":"mdd.sql.signed-comparison-readback.v1","status":"passed-scoped",
              "pre_fix_observation":str(BEFORE.relative_to(ROOT)),"post_fix_observation":str(AFTER.relative_to(ROOT)),
              "source_sha256":after["source_sha256"],"readback_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "base_readback_sha256":hashlib.sha256((HERE / "readback.py").read_bytes()).hexdigest(),
              "raw_command_hashes_verified":True,"fixed_legacy_engines":["A0","A1"],
              "literal_comparisons_with_null":7,"affinity_cases_explicitly_unsupported":2,
              "legacy_text_arithmetic":"A0/A1 return 1; candidate reports unsupported, not equivalent",
              "negative_controls_rejected":negatives,"profile_admitted":False,
              "limits":["No CAST, CTE or column affinity qualification, including same-storage-class cases.",
                        "No HostLab full corpus or performance qualification."]}
    (AFTER / "readback.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":report["status"],"literal_cases":7,"unsupported_affinity_cases":2,"negative_controls":negatives}))


if __name__ == "__main__":
    main()
