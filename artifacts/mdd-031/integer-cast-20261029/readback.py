"""Independently recompute value equality and DTO differences from raw outputs."""
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
RUN = HERE / "runs/20261028T174502714475Z"
REFERENCE = ROOT / "artifacts/mdd-031-audit/integer-cast-observations/run-20261028T174032300709Z"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cell_value(cell):
    if cell["type"] == "null": return None
    require(cell["type"] in {"i64", "u64", "int64", "uint64"}, "integer type mismatch")
    return int(cell["value"])


def compare(candidate, refs):
    require(candidate["probe_complete"] and not candidate["profile_admitted"], "candidate terminal mismatch")
    comparisons = []
    for dialect in candidate["dialects"]:
        engine = {"010":"A0", "011":"A1"}[dialect["dialect"]]
        snapshot_ids = []
        for kind, key in [("literals","literal_cases"),("dex","dex_cases")]:
            actual = {item["id"]:item for item in dialect[key]}
            ref = refs[(engine,kind)]
            require(set(actual) == set(ref), "case set mismatch")
            ids = {item["result"]["binding"]["snapshot_id"] for item in actual.values()}
            require(len(ids) == 1, "mixed snapshots in result scope")
            snapshot_ids.append(next(iter(ids)))
            differences = []
            for name, item in actual.items():
                result = item["result"]
                require(result["calculation_complete"] and not result["profiles_admitted"] and len(result["rows"]) == 1 and len(result["rows"][0]) == 1, "candidate result incomplete")
                sql = item["sql"] if kind == "literals" else item["sql"].replace("native_strings", "strings")
                require(sql == ref[name]["sql"], "query mismatch")
                cell, expected = result["rows"][0][0], ref[name]["cell"]
                require(cell_value(cell) == cell_value(expected), "integer value mismatch: " + name)
                kind_name = {"i64":"int64","u64":"uint64","null":"null"}[cell["type"]]
                if kind_name != expected["type"]: differences.append({"id":name,"reference":expected["type"],"candidate":kind_name})
            comparisons.append({"engine":engine,"kind":kind,"cases":len(actual),"integer_values_equal":True,"dto_type_differences":differences})
        require(snapshot_ids[0] != snapshot_ids[1], "distinct fixture snapshots collapsed")
    return comparisons


def main():
    report = json.loads((RUN / "qualification.json").read_text(encoding="utf-8"))
    require(report["status"] == "passed-value-only" and not report["profiles_admitted"], "scope mismatch")
    for path, expected in report["source_sha256"].items():
        require(sha(ROOT / path) == expected, "source changed: " + path)
    require(sha(REFERENCE / "summary.json") == report["reference_summary_sha256"] and sha(REFERENCE / "readback.json") == report["reference_readback_sha256"], "reference summary changed")
    for name in ("build", "compile", "candidate"):
        folder = RUN / name
        record = json.loads((folder / "record.json").read_text(encoding="utf-8"))
        require(record["exit_code"] == 0, name + " failed")
        for stream in ("stdout", "stderr"):
            require(sha(folder / (stream + ".txt")) == record[stream + "_sha256"], name + " output hash mismatch")
    exe = RUN / "probe.exe"
    require(not exe.is_file() or sha(exe) == report["candidate_binary_sha256"], "candidate binary mismatch")
    summary = json.loads((REFERENCE / "summary.json").read_text(encoding="utf-8"))
    references = {}
    for record in summary["records"]:
        engine, kind = record["variant"], record["kind"]
        folder = REFERENCE / (engine + "-" + kind)
        path = folder / (engine + ".observations.json")
        require(sha(path) == record["observations_sha256"], "reference observation changed")
        data = json.loads(path.read_text(encoding="utf-8"))
        require(data["client_context_exited"] and sha(folder / (engine + ".sdk-transcript.jsonl")) == data["transcript_sha256"], "reference process/transcript mismatch")
        cases = {}
        for case in data["cases"]:
            require(case["close"]["body"].get("closed") is True, "reference dataset not closed")
            response = case["statements"][0]["response"]
            require(not response["is_error"], "reference query failed")
            statement = response["body"]["statements"][0]
            require(statement["total_rows"] == 1 and not statement["truncated"] and statement["next_offset"] is None, "reference response truncated")
            cases[case["id"]] = {"sql":case["statements"][0]["sql"], "cell":statement["rows"][0][0]}
        end = data["active_dataset_after_all_cases"]["body"]
        require(not end["datasets"] and end["usage"]["datasets"] == 0 and end["usage"]["input_bytes"] == 0, "reference dataset leak")
        references[(engine,kind)] = cases
    require(set(references) == {("A0","literals"),("A0","dex"),("A1","literals"),("A1","dex")}, "reference set mismatch")
    candidate = json.loads((RUN / "candidate/stdout.txt").read_text(encoding="utf-8"))
    computed = compare(candidate, references)
    require(computed == report["comparisons"], "comparison or DTO difference ledger mismatch")
    negatives = []
    for name in ("wrong_value", "missing_case", "hidden_dto_difference"):
        altered = copy.deepcopy(candidate)
        if name == "wrong_value": altered["dialects"][0]["literal_cases"][0]["result"]["rows"][0][0]["value"] = "99"
        elif name == "missing_case": altered["dialects"][0]["dex_cases"].pop()
        else: altered["dialects"][0]["literal_cases"][0]["result"]["rows"][0][0]["type"] = "u64"
        try:
            computed_bad = compare(altered, references)
            require(computed_bad == report["comparisons"], "difference ledger changed")
        except RuntimeError:
            negatives.append(name)
        else:
            raise RuntimeError("negative control accepted: " + name)
    output = {"schema_version":"mdd.sql.integer-cast-readback.v1","status":"passed-value-only","cases":sum(item["cases"] for item in computed),
              "dto_type_differences":sum(len(item["dto_type_differences"]) for item in computed),"source_sha256":report["source_sha256"],
              "readback_sha256":sha(Path(__file__).resolve()),"raw_command_and_reference_hashes_verified":True,
              "negative_controls_rejected":negatives,"profiles_admitted":False,
              "limits":report["limits"]}
    (RUN / "readback.json").write_text(json.dumps(output,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":output["status"],"cases":output["cases"],"dto_type_differences":output["dto_type_differences"],"negative_controls":negatives}))


if __name__ == "__main__":
    main()
