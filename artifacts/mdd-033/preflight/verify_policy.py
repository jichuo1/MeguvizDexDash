"""Offline exact readback of this limited observed policy, with explicit -O gates."""
from pathlib import Path
import copy
import json
import sys
from probe_temp_policy import ROOT, OUT, CASES, FIXTURE, FIXTURE_SHA, digest, require, dump

# These expectations freeze actual observations of the pinned versions, not a
# presumption that the new engine already implements or admits the profile.
OK = (False, None)
def VALUE(number):
    return (False, number)
def ERROR(message):
    return (True, message)

EXPECTED = {
    "table-if-not-exists": [OK, OK, VALUE(1), OK, VALUE(1)],
    "view-if-not-exists": [OK, OK, VALUE(1), OK, VALUE(1)],
    "table-drop-if-exists": [OK, ERROR("no such table: absent"), OK, OK, ERROR("unknown relation `item`"), OK],
    "view-drop-if-exists": [OK, ERROR("no such view: absent"), OK, OK, ERROR("unknown relation `item`"), OK],
    "table-then-view-same-name": [OK, OK, VALUE(2), ERROR("use DROP VIEW to delete item"), VALUE(2)],
    "view-then-table-same-name": [OK, OK, VALUE(2), ERROR("use DROP TABLE to delete item"), VALUE(2)],
    "table-then-view-if-not-exists": [OK, OK, VALUE(1), ERROR("use DROP TABLE to delete item"), VALUE(1)],
    "view-then-table-if-not-exists": [OK, OK, VALUE(1), ERROR("use DROP VIEW to delete item"), VALUE(1)],
    "drop-view-on-table": [OK, ERROR("use DROP TABLE to delete item"), VALUE(1)],
    "drop-table-on-view": [OK, ERROR("use DROP VIEW to delete item"), VALUE(1)],
    "drop-view-if-exists-on-table": [OK, ERROR("use DROP TABLE to delete item"), VALUE(1)],
    "drop-table-if-exists-on-view": [OK, ERROR("use DROP VIEW to delete item"), VALUE(1)],
}
for key in ["forward-table", "forward-view", "forward-table-if-not-exists", "forward-view-if-not-exists"]:
    EXPECTED[key] = [ERROR("unknown relation `future`"), ERROR("unknown relation `derived`"), OK, ERROR("unknown relation `derived`")]

def normalize(response):
    require(response["is_error"] == response["mcp_result"]["isError"], "tool error flag drift")
    require(response["body"] == response["mcp_result"]["structuredContent"], "parsed body differs from actual structuredContent")
    if response["is_error"]:
        error = response["body"]["error"]
        require(error["kind"] == "invalid_query" and error["stage"] == "execute_sql" and error["statement_index"] == 0, "observed error taxonomy/stage mismatch")
        return (True, error["message"]), {"error": error}
    statements = response["body"]["statements"]
    require(len(statements) == 1 and statements[0]["statement_index"] == 0, "missing or extra statement results")
    statement = statements[0]
    require(statement.get("next_offset") is None and not statement.get("truncated", False), "tiny policy result not fully consumed")
    if statement["kind"] == "query":
        rows = statement["rows"]
        require(len(rows) == 1 and len(rows[0]) == 1, "expected exactly one scalar row")
        require(rows[0][0]["type"] == "uint64", "exact scalar type changed")
        return VALUE(int(rows[0][0]["value"])), {"kind": statement["kind"], "columns": statement["columns"], "rows": rows}
    require(statement["kind"] in ["create_temp_table", "drop_definition"] and statement["rows"] == [], "DDL result metadata changed")
    return OK, {"kind": statement["kind"], "columns": statement["columns"], "rows": statement["rows"]}

def verify_observations(record, directory):
    require(record["client_context_exited"] is True, "MCP context did not exit")
    require([case["id"] for case in record["cases"]] == [name for name, _ in CASES], "scenario set/order changed")
    require(len(set(case["dataset_id"] for case in record["cases"])) == 16, "scenarios did not use independent datasets")
    transcript = directory / (record["variant"] + ".sdk-transcript.jsonl")
    require(digest(transcript) == record["transcript_sha256"], "transcript changed")
    lines = [json.loads(line) for line in transcript.read_text(encoding="utf-8").splitlines()]
    require(lines[0]["kind"] == "initialized_server_info", "missing initialized server identity")
    calls = lines[1:]
    require(len(calls) == 206, "expected every open/query/close/final list request and response")
    for index in range(0, len(calls), 2):
        require(calls[index]["direction"] == "request" and calls[index+1]["direction"] == "response" and calls[index]["tool"] == calls[index+1]["tool"], "SDK transcript request/response pairing mismatch")
    expected_calls = []
    for case in record["cases"]:
        expected_calls.extend([("open_dataset", {"inputs": [str(FIXTURE)]}, case["open"])])
        statements = dict(CASES)[case["id"]]
        require(len(case["statements"]) == len(statements) == len(EXPECTED[case["id"]]), "statement count changed")
        require(case["close"]["is_error"] is False and case["close"]["body"] == {"closed": True, "dataset_id": case["dataset_id"]}, "dataset was not explicitly closed")
        for ordinal, statement in enumerate(case["statements"]):
            require(statement["ordinal"] == ordinal and statement["sql"] == statements[ordinal], "request SQL/order changed")
            expected_calls.append(("query", {"dataset_id": case["dataset_id"], "sql": [statement["sql"]], "limit": 10, "offset": 0}, statement["response"]))
        expected_calls.append(("close_dataset", {"dataset_id": case["dataset_id"]}, case["close"]))
    expected_calls.append(("list_datasets", {}, record["active_dataset_after_all_cases"]))
    for index, (tool, arguments, result) in enumerate(expected_calls):
        require(calls[index*2] == {"direction": "request", "tool": tool, "arguments": arguments} and calls[index*2+1] == {"direction": "response", "tool": tool, "result": result}, "record differs from complete SDK transcript")
    remaining = record["active_dataset_after_all_cases"]["body"]
    require(remaining["datasets"] == [] and remaining["usage"] == {"datasets": 0, "input_bytes": 0} and remaining["admitted_requests"] == 0 and remaining["running_requests"] == 0, "live dataset/work remained")
    normalized = {}
    for case in record["cases"]:
        normalized[case["id"]] = []
        for ordinal, statement in enumerate(case["statements"]):
            value, complete = normalize(statement["response"])
            require(value == EXPECTED[case["id"]][ordinal], "pinned TEMP policy observation changed: " + case["id"] + ":" + str(ordinal))
            normalized[case["id"]].append(complete)
    return normalized

def main():
    directory = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else sorted(path.parent for path in OUT.glob("*/summary.json"))[-1]
    require(directory.is_relative_to(OUT), "readback outside assigned preflight path")
    summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    require(summary["MDD033_done"] is False and summary["profiles_admitted"] is False and summary["formal_measurement"] is False and summary["private_input_parsed"] is False, "scope/qualification changed")
    require(summary["driver_sha256"] == digest(OUT / "probe_temp_policy.py"), "driver differs from this run")
    require(digest(FIXTURE) == FIXTURE_SHA and FIXTURE.stat().st_size == 660, "tiny input identity changed")
    normalized = []
    records = []
    for row in summary["records"]:
        path = ROOT / row["observations_path"]
        require(path.resolve().is_relative_to(directory) and digest(path) == row["observations_sha256"], "observation hash/path changed")
        record = json.loads(path.read_text(encoding="utf-8"))
        records.append(record)
        require(digest(Path(record["engine_path"])) == record["engine_sha256"], "actual pinned engine changed")
        normalized.append(verify_observations(record, directory))
    require(normalized[0] == normalized[1], "pinned A0/A1 policy results differ")
    wrong = copy.deepcopy(records[0])
    wrong["cases"][0]["close"]["body"]["closed"] = False
    try:
        verify_observations(wrong, directory)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("broken close receipt accepted")
    dump(directory / "policy-readback.json", {"schema_version": "mdd.temp-policy-preflight-readback.v1", "passed": True, "variants": 2, "independent_datasets_per_variant": 16, "statements_per_variant": 70, "sdk_tool_calls_verified_per_variant": 103, "all_datasets_closed": True, "final_dataset_usage_zero": True, "cross_version_complete_policy_results_equal": True, "broken_close_receipt_rejected": True, "profile_admitted": False, "MDD033_done": False, "policy_results": normalized[0], "not_verified": ["cycles", "syntax-invalid IF NOT EXISTS body parsing", "atomic multi-statement rollback", "native MDD catalog/cursor", "epoch values exposed by reference engine", "cross-session TEMP visibility", "private inputs", "performance"]})
    print(json.dumps({"readback": (directory / "policy-readback.json").relative_to(ROOT).as_posix(), "passed": True, "variants": 2, "statements_per_variant": 70, "MDD033_done": False}))

if __name__ == "__main__":
    main()
