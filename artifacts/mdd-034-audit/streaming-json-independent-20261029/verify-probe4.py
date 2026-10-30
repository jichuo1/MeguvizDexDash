from pathlib import Path
import base64
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


checks = {}
sources = read(HERE / "source-before.json")["sha256"]
drift = [name for name, sha in sources.items() if not (ROOT / name).is_file() or digest(ROOT / name) != sha]
checks["source_identity_59_unchanged"] = len(sources) == 59 and not drift
for phase in ("build4", "probe4"):
    record = read(HERE / phase / "record.json")
    admission = read(HERE / (phase + "-admission.json"))
    checks[phase + "_admission"] = admission["admitted"] is True and int(admission["minimum_bytes"]) == 3 * 1024**3 and int(admission["available_physical_bytes"]) >= int(admission["minimum_bytes"])
    checks[phase + "_process"] = record["exit_code"] == 0 and record["timed_out"] is False and record["tree_empty_verified"] is True
    checks[phase + "_logs"] = all(digest(HERE / phase / name) == record[key] for name, key in (("stdout.txt", "stdout_sha256"), ("stderr.txt", "stderr_sha256"), ("supervisor.json", "supervisor_sha256"))) and digest(HERE / (phase + "-admission.json")) == record["admission_sha256"]

payload = read(HERE / "probe4/stdout.txt")
records = {(r["case"], r["mode"]): r for r in payload["records"]}
expected_cases = {("large_bytes", m) for m in ("low_output", "low_workspace", "success", "cancel_count", "sibling_reduce", "sibling_grow")} | {("all_values", "success")}
checks["seven_distinct_scenarios"] = len(payload["records"]) == 7 and set(records) == expected_cases
checks["profile_not_admitted"] = payload["profile_admitted"] is False

wire = json.dumps([{"type": "bytes", "value": base64.b64encode(bytes(i % 251 for i in range(524288))).decode("ascii")}], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
wire_sha = hashlib.sha256(wire).hexdigest()
for mode in ("success", "sibling_reduce"):
    r = records[("large_bytes", mode)]
    checks[mode + "_independent_large_bytes"] = r["expected_row_bytes"] == len(wire) == r["consumer_reencoded_bytes"] == r["output_before"] == r["queue_before"] and r["expected_consumer_json_sha256"] == wire_sha == r["consumer_reencoded_sha256"] and r["received"][0][0]["value"] == base64.b64encode(bytes(i % 251 for i in range(524288))).decode("ascii")

for key in (("large_bytes", "success"), ("large_bytes", "sibling_reduce"), ("all_values", "success")):
    r = records[key]
    label = "_".join(key)
    checks[label + "_delivery"] = r["status_before_receive"]["execution_complete"] is True and r["status_before_receive"]["delivery_complete"] is False and r["status_after"]["delivery_complete"] is True and r["end"]["status"] == "ok" and r["final"]["envelope"]["operation_status"] == "ok" and r["queue_after_receive"] == 0 and r["workspace_held"] > 0 and r["workspace_after_ack"] == 0
    checks[label + "_wire_count"] = r["expected_row_bytes"] == r["consumer_reencoded_bytes"] == r["queue_before"] == r["output_before"] and r["expected_consumer_json_sha256"] == r["consumer_reencoded_sha256"]

values = records[("all_values", "success")]["received"][0]
checks["all_types_and_exact_values"] = values[:6] == [{"type": "null"}, {"type": "bool", "value": True}, {"type": "i64", "value": "-9223372036854775808"}, {"type": "u64", "value": "18446744073709551615"}, {"type": "utf16", "value": [0, 55296, 56320, 65535]}, {"type": "bytes", "value": "AAEC/w=="}] and values[6]["type"] == "entity" and values[6]["value"]["dex_occurrence_id"] == 'dex-"\n雪' and values[6]["value"]["kind"] == "method_definition" and values[6]["value"]["local_index"] == 42 and values[6]["value"]["snapshot_id"] == records[("all_values", "success")]["final"]["envelope"]["snapshot_id"]

for mode, code, budget in (("low_output", "QUOTA_EXCEEDED", "output_bytes"), ("low_workspace", "QUOTA_EXCEEDED", "query_workspace_bytes"), ("cancel_count", "CANCELLED", None), ("sibling_grow", "QUOTA_EXCEEDED", "output_bytes")):
    r = records[("large_bytes", mode)]
    envelope = r["final"]["envelope"]
    checks[mode + "_no_false_completion"] = not r["received"] and r["queue_before"] == 0 and r["output_before"] == 0 and r["workspace_before"] == 0 and r["status_after"]["delivery_complete"] is False and r["end"]["error"]["code"] == code and envelope["error"]["code"] == code and envelope["execution"]["complete"] is False and envelope["response"]["truncated"] is True and (budget is None or envelope["error"]["details"]["budget"] == budget)
checks["low_output_partial_length"] = records[("large_bytes", "low_output")]["end"]["error"]["details"]["encoded_length_exact"] is False
checks["sibling_grow_only_sibling_charge"] = records[("large_bytes", "sibling_grow")]["global_output_after"] == 1

binary = ROOT / "artifacts/local/streaming-json-independent-20261029-target/debug/mdd-streaming-json-independent.exe"
checks["binary_present"] = binary.is_file()
output = {"checks": checks, "source_drift": drift, "binary_sha256": digest(binary) if binary.is_file() else None, "scope": "synthetic in-process query-bound executor and queue; consumer re-encoding reference only; no real worker/transport, complete profile, RSS, or performance qualification"}
print(json.dumps(output, ensure_ascii=False, indent=2))
raise SystemExit(0 if all(checks.values()) else 1)
