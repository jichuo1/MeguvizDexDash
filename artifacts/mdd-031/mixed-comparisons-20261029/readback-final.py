"""Recompute final literal/CAST/IN observations from saved process evidence."""
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
AFTER = HERE / "runs/20261028T173157850568Z"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prior = load("mdd_mixed_readback", "readback.py")
signed = load("mdd_signed_readback", "readback-signed.py")
observer = load("mdd_mixed_observer", "observe.py")


def verify_extra(observed):
    signed.verify_extra(observed)
    cases = {case["id"]:case for case in observed["cases"]}
    expected = {"cast_bad":0,"cast_prefix":123,"literal_in":0,"cast_in":1,"derived_in":1,"derived_not_in":0}
    for name, value in expected.items():
        case = cases[name]
        prior.require(case["sqlite_value"] == value, "SQLite expected value differs")
        for engine in ("A0", "A1"):
            prior.require(case["engines"][engine]["exit_code"] == 0 and case["engines"][engine]["display_value"] == str(value), "fixed engine value differs")
        for dialect in ("bridge-native", "bridge-010", "bridge-011"):
            item = case["engines"][dialect]
            if name == "literal_in":
                prior.require(item["exit_code"] == 0 and item["result"]["result"]["rows"][0][0] == {"type":"i64", "value":"0"}, "literal IN mismatch")
            else:
                code = "INVALID_ARGUMENT" if name in {"cast_bad", "cast_prefix"} and dialect == "bridge-native" else "UNSUPPORTED_QUERY"
                prior.require(item["exit_code"] != 0 and item["result"]["error"]["code"] == code, "unqualified capability was not blocked")


def main():
    before = json.loads((BEFORE / "observations.json").read_text(encoding="utf-8"))
    after = json.loads((AFTER / "observations.json").read_text(encoding="utf-8"))
    identities = json.loads((AFTER / "wrapper-identity.json").read_text(encoding="utf-8"))
    prior.require(prior.digest((HERE / "observe.py").read_bytes()) == identities["observer_sha256"], "observer changed")
    prior.require(prior.digest((HERE / "observe-final.py").read_bytes()) == identities["wrapper_sha256"], "wrapper changed")
    for path, sha in after["source_sha256"].items():
        prior.require(prior.digest((ROOT / path).read_bytes()) == sha, "source mismatch " + path)
    for name, (path, sha) in observer.ENGINES.items():
        prior.require(prior.digest(path.read_bytes()) == sha, name + " identity mismatch")
    prior.require(prior.digest(observer.FIXTURE.read_bytes()) == before["fixture_sha256"] == after["fixture_sha256"], "fixture mismatch")
    prior.verify_run(BEFORE, before)
    prior.verify_run(AFTER, after)
    baseline = copy.deepcopy(after)
    base_ids = {case["id"] for case in before["cases"]}
    baseline["cases"] = [case for case in baseline["cases"] if case["id"] in base_ids]
    prior.check_results(before, baseline)
    verify_extra(after)
    negatives = []
    for name in ("literal_wrong", "derived_falsely_successful", "cast_falsely_successful"):
        changed = copy.deepcopy(after)
        cases = {case["id"]:case for case in changed["cases"]}
        if name == "literal_wrong": cases["literal_in"]["engines"]["bridge-010"]["result"]["result"]["rows"][0][0]["value"] = "1"
        elif name == "derived_falsely_successful": cases["derived_in"]["engines"]["bridge-010"]["exit_code"] = 0
        else: cases["cast_bad"]["engines"]["bridge-010"]["exit_code"] = 0
        try:
            verify_extra(changed)
        except RuntimeError:
            negatives.append(name)
        else:
            raise RuntimeError("negative control accepted: " + name)
    report = {"schema_version":"mdd.sql.affinity-scope-readback.v1","status":"passed-scoped",
              "pre_fix_observation":str(BEFORE.relative_to(ROOT)),"final_observation":str(AFTER.relative_to(ROOT)),
              "source_sha256":after["source_sha256"],"readback_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "raw_command_hashes_verified":True,"fixed_legacy_engines":["A0","A1"],"query_count":len(after["cases"]),
              "negative_controls_rejected":negatives,"profile_admitted":False,
              "limits":["Literal/parameter comparisons without affinity and provably typed direct-table IN only.",
                        "SQLite CAST, CTE and derived-table affinity still unsupported; no full SQL or HostLab qualification.",
                        "Legacy CAST('bad' AS INTEGER) and 1+'a' return values; candidate reports unsupported, not equivalent."]}
    (AFTER / "readback.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":report["status"],"query_count":report["query_count"],"negative_controls":negatives,"profile_admitted":False}))


if __name__ == "__main__":
    main()
