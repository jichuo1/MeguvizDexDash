"""Read existing fixed-engine and candidate evidence; do not infer unobserved optimizer rules."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
REFERENCE = ROOT / "artifacts/mdd-031-audit/integer-cast-observations/run-20261028T174032300709Z"
CANDIDATE = ROOT / "artifacts/mdd-031/integer-cast-20261029/runs/20261028T174502714475Z"
HOST_BATCH = ROOT / "conformance/corpus/hostlab/source-8782f43/analysis_batch.py"
HOST_PAGING = ROOT / "conformance/corpus/hostlab/source-8782f43/analysis_paging.py"


def require(condition, reason):
    if not condition: raise RuntimeError(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sample(ref, candidate, name, kind):
    item = next(value for value in ref["cases"] if value["id"] == name)
    response = item["statements"][0]["response"]
    require(not response["is_error"] and item["close"]["body"]["closed"] is True, "reference query incomplete")
    statement = response["body"]["statements"][0]
    require(statement["total_rows"] == 1 and not statement["truncated"] and statement["next_offset"] is None, "reference page incomplete")
    actual = next(value for value in candidate["literal_cases" if kind == "literals" else "dex_cases"] if value["id"] == name)
    result = actual["result"]
    require(result["calculation_complete"] and len(result["rows"]) == 1, "candidate incomplete")
    a, b = statement["rows"][0][0], result["rows"][0][0]
    require(a.get("value") == b.get("value"), "different projected values")
    return {"id":name,"kind":kind,"reference_column":statement["columns"][0],"reference_cell":a,
            "candidate_column_name":result["columns"][0],"candidate_cell":b,
            "extracted_cell_values_equal":True,"complete_envelope_equal":False}


def main():
    summary = json.loads((REFERENCE / "summary.json").read_text(encoding="utf-8"))
    candidate_report = json.loads((CANDIDATE / "qualification.json").read_text(encoding="utf-8"))
    candidate_record = json.loads((CANDIDATE / "candidate/record.json").read_text(encoding="utf-8"))
    require(candidate_record["exit_code"] == 0 and sha(CANDIDATE / "candidate/stdout.txt") == candidate_record["stdout_sha256"], "candidate raw hash")
    candidate = json.loads((CANDIDATE / "candidate/stdout.txt").read_text(encoding="utf-8"))
    batch = HOST_BATCH.read_text(encoding="utf-8")
    paging = HOST_PAGING.read_text(encoding="utf-8")
    require('"rows": [[c["value"] for c in row] for row in statement["rows"]]' in batch and '"typed_result": raw' in batch, "HostLab batch source changed")
    require('result["rows"] != [[cell["value"] for cell in row] for row in rows]' in paging, "HostLab paging source changed")
    references = {}
    for entry in summary["records"]:
        name,kind = entry["variant"],entry["kind"]
        path = REFERENCE / (name + "-" + kind) / (name + ".observations.json")
        require(sha(path) == entry["observations_sha256"], "reference hash mismatch")
        references[(name,kind)] = json.loads(path.read_text(encoding="utf-8"))
    results = []
    for dialect in candidate["dialects"]:
        engine = {"010":"A0","011":"A1"}[dialect["dialect"]]
        for kind,name in [("literals","empty"),("literals","prefix"),("literals","negative_decimal"),("literals","max"),("literals","null"),("dex","string_0")]:
            results.append({"engine":engine, **sample(references[(engine,kind)], dialect, name, kind)})
    require(len(candidate_report["comparisons"]) == 4 and sum(len(item["dto_type_differences"]) for item in candidate_report["comparisons"]) == 30, "previous type ledger changed")
    for engine in ("A0","A1"):
        literal = next(item for item in results if item["engine"] == engine and item["id"] == "empty")
        source = next(item for item in results if item["engine"] == engine and item["id"] == "string_0")
        require(literal["reference_cell"] == {"type":"uint64","value":"0"}, "literal counterexample changed")
        require(source["reference_cell"] == {"type":"int64","value":"0"}, "source counterexample changed")
        require(literal["reference_column"]["data_type"] == source["reference_column"]["data_type"] == "sqlite_dynamic", "schema distinction changed")
    output = {"schema_version":"mdd.sql.dto-origin-observation.v1","status":"observed-no-general-rule",
              "source_sha256":{"host_batch":sha(HOST_BATCH),"host_paging":sha(HOST_PAGING),"candidate_stdout":sha(CANDIDATE / "candidate/stdout.txt"),
                               "reference_summary":sha(REFERENCE / "summary.json"),"analyzer":sha(Path(__file__).resolve())},
              "examples":results,"known_candidate_dto_type_differences":30,"profiles_admitted":False,
              "findings":["Old column schema reports sqlite_dynamic for both literal and source cases, yet their zero cell tags differ.",
                          "Fixed HostLab batch extracts cell values while retaining the complete typed_result; paging verifies the extracted values against that result.",
                          "The value-only extraction does not prove full DTO, pagination, profile or B0 equivalence.",
                          "No optimizer or serializer causal rule can be established from these observations alone."]}
    (HERE / "observation.json").write_text(json.dumps(output,indent=2,ensure_ascii=True)+"\n",encoding="utf-8")
    print(json.dumps({"status":output["status"],"examples":len(results),"known_type_differences":30,"profile_admitted":False}))


if __name__ == "__main__": main()
