"""Validate fixed-engine comparison observations, including intentionally unsupported affinity."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
BEFORE = HERE / "runs/20261028T171200202170Z"
AFTER = HERE / "runs/20261028T171500723057Z"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def table_value(data):
    rows = [[part.strip() for part in line.strip("|").split("|")] for line in data.decode("utf-8").splitlines() if line.startswith("|")]
    require(len(rows) == 2 and rows[0] == ["v"] and len(rows[1]) == 1, "reference table incomplete")
    return rows[1][0]


def check_results(before, after):
    old = {case["id"]:case for case in before["cases"]}
    new = {case["id"]:case for case in after["cases"]}
    safe = {"numeric_text_equal":0,"numeric_text_order":1,"text_blob_order":1,"numeric_blob_unequal":1,"float_text_equal":0,"null_compare":None}
    guarded = {"cast_text_affinity", "cte_text_affinity"}
    require(set(old) == set(new) == set(safe) | guarded, "comparison case set differs")
    for name, expected in safe.items():
        require(new[name]["sqlite_value"] == expected, "SQLite expected mismatch")
        for engine in ("A0", "A1"):
            require(old[name]["engines"][engine]["exit_code"] == 0 and new[name]["engines"][engine]["display_value"] == ("NULL" if expected is None else str(expected)), "fixed engine value differs")
        for dialect in ("bridge-native", "bridge-010", "bridge-011"):
            item = new[name]["engines"][dialect]
            require(item["exit_code"] == 0 and item["result"]["operation_status"] == "ok", "candidate expected success")
            rows = item["result"]["result"]["rows"]
            require(len(rows) == 1 and len(rows[0]) == 1, "candidate result truncated")
            cell = rows[0][0]
            require(cell["type"] == ("null" if expected is None else "i64") and (expected is None or int(cell["value"]) == expected), "candidate value mismatch")
            if name != "null_compare":
                error = old[name]["engines"][dialect]
                require(error["exit_code"] != 0 and error["result"]["error"]["code"] == "INVALID_ARGUMENT", "pre-fix regression absent")
    for name in guarded:
        require(new[name]["sqlite_value"] == 1, "affinity oracle differs")
        for engine in ("A0", "A1"):
            require(new[name]["engines"][engine]["exit_code"] == 0 and new[name]["engines"][engine]["display_value"] == "1", "fixed affinity result differs")
        for dialect in ("bridge-native", "bridge-010", "bridge-011"):
            item = new[name]["engines"][dialect]
            require(item["exit_code"] != 0 and item["result"]["error"]["code"] == "UNSUPPORTED_QUERY", "affinity gap not explicitly blocked")


def verify_run(folder, observation):
    build = json.loads((folder / "build/record.json").read_text(encoding="utf-8"))
    require(build["exit_code"] == 0, "build failed")
    for stream in ("stdout", "stderr"):
        require(digest((folder / "build" / (stream + ".txt")).read_bytes()) == build[stream + "_sha256"], "build hash mismatch")
    sqlite = sqlite3.connect(":memory:")
    for case in observation["cases"]:
        require(case["sqlite_version"] == sqlite3.sqlite_version and sqlite.execute(case["sql"]).fetchone()[0] == case["sqlite_value"], "SQLite readback differs")
        for name, item in case["engines"].items():
            case_dir = folder / name / case["id"]
            record = json.loads((case_dir / "record.json").read_text(encoding="utf-8"))
            require(record["exit_code"] == item["exit_code"] and not record["timed_out"], "process terminal mismatch")
            for stream in ("stdout", "stderr"):
                require(digest((case_dir / (stream + ".txt")).read_bytes()) == record[stream + "_sha256"], "output hash mismatch")
            stdout = (case_dir / "stdout.txt").read_bytes()
            if name.startswith("bridge-"):
                require(json.loads(stdout) == item["result"], "candidate observation differs from raw output")
            elif item["exit_code"] == 0:
                require(table_value(stdout) == item["display_value"], "legacy display differs from raw output")


def main():
    before = json.loads((BEFORE / "observations.json").read_text(encoding="utf-8"))
    after = json.loads((AFTER / "observations.json").read_text(encoding="utf-8"))
    require(not before["profile_admitted"] and not after["profile_admitted"], "profile incorrectly admitted")
    for name, sha in after["source_sha256"].items():
        require(digest((ROOT / name).read_bytes()) == sha, "current source mismatch: " + name)
    require(before["source_sha256"]["Cargo.lock"] == after["source_sha256"]["Cargo.lock"], "lock changed between runs")
    fixture = ROOT / "tests/fixtures/references/generated/classic-035.dex"
    require(digest(fixture.read_bytes()) == before["fixture_sha256"] == after["fixture_sha256"], "fixture mismatch")
    verify_run(BEFORE, before)
    verify_run(AFTER, after)
    check_results(before, after)
    negatives = []
    for name in ("wrong_result", "affinity_success", "missing_case"):
        changed = copy.deepcopy(after)
        if name == "wrong_result": changed["cases"][0]["engines"]["bridge-010"]["result"]["result"]["rows"][0][0]["value"] = "1"
        elif name == "affinity_success": changed["cases"][-1]["engines"]["bridge-010"]["exit_code"] = 0
        else: changed["cases"].pop()
        try:
            check_results(before, changed)
        except RuntimeError:
            negatives.append(name)
        else:
            raise RuntimeError("negative control accepted: " + name)
    report = {"schema_version":"mdd.sql.literal-comparison-readback.v1", "status":"passed-scoped",
              "pre_fix_observation":str(BEFORE.relative_to(ROOT)), "post_fix_observation":str(AFTER.relative_to(ROOT)),
              "fixture_sha256":after["fixture_sha256"], "fixed_legacy_engines":["A0", "A1"],
              "source_sha256":after["source_sha256"], "readback_sha256":digest(Path(__file__).read_bytes()),
              "independent_sqlite_version":sqlite3.sqlite_version, "literal_cases_with_null":6, "still_unsupported_affinity_cases":2,
              "raw_command_hashes_verified":True, "negative_controls_rejected":negatives, "profile_admitted":False,
              "limits":["Literal and parameter operands without affinity only; columns, casts, and CTE type affinity are not qualified.",
                        "SQLite and legacy oracle outputs are tiny synthetic observations, not real HostLab audit or performance."]}
    (AFTER / "readback.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":"passed-scoped","literal_cases_with_null":6,"still_unsupported_affinity_cases":2,"negative_controls":negatives}))


if __name__ == "__main__":
    main()
