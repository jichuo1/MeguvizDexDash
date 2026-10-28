"""Verify captured fixed-engine observations, retaining exact evidence scope."""
from pathlib import Path
import hashlib
import json
import sys

directory = Path(sys.argv[1])
expected = {
    "positive": ("utf8", "bcd"), "negative_start": ("utf8", "de"),
    "negative_length": ("utf8", "bc"), "nul": ("utf8", "\x00B"),
    "supplementary": ("utf8", "😀"), "null": ("null", None),
    "bytes": ("utf8", "B"), "substring": ("utf8", "bcd"),
}
identities = {"A0":"f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448", "A1":"602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6"}
summary = json.loads((directory / "summary.json").read_text(encoding="utf8"))
records = {item["variant"]: item for item in summary["records"]}
for name in ("A0", "A1"):
    path = directory / f"{name}.observations.json"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != records[name]["observations_sha256"]: raise RuntimeError(f"{name} observation digest")
    report = json.loads(path.read_text(encoding="utf8"))
    transcript = directory / f"{name}.sdk-transcript.jsonl"
    if hashlib.sha256(transcript.read_bytes()).hexdigest() != report["transcript_sha256"]: raise RuntimeError(f"{name} transcript digest")
    if report["engine_sha256"] != identities[name] or not report.get("client_context_exited"): raise RuntimeError(f"{name} engine identity or close")
    cases = {x["id"]: x for x in report["cases"]}
    if set(cases) != set(expected): raise RuntimeError(f"{name} case set")
    for case_id, want in expected.items():
        case = cases[case_id]
        if case["close"]["is_error"] or case["close"]["body"].get("closed") is not True: raise RuntimeError(f"{name}/{case_id} close")
        response = case["statements"][0]["response"]
        if response["is_error"]: raise RuntimeError(f"{name}/{case_id} query error")
        statement = response["body"]["statements"][0]
        if statement.get("truncated") is not False or statement.get("total_rows") != 1 or statement.get("next_offset") is not None: raise RuntimeError(f"{name}/{case_id} incomplete")
        value = statement["rows"][0][0]
        if (value["type"], value.get("value")) != want: raise RuntimeError(f"{name}/{case_id} value")
    final = report["active_dataset_after_all_cases"]
    body = final["body"]
    if final["is_error"] or body["datasets"] or body["usage"]["input_bytes"] != 0 or body["usage"]["datasets"] != 0 or body["running_requests"] != 0 or body["admitted_requests"] != 0: raise RuntimeError(f"{name} resources not closed")
print(json.dumps({"status":"pass", "engines":["A0","A1"], "cases_per_engine":len(expected), "scope":"fixed DexSQL substr examples, not legacy SQLite profile or performance qualification", "profiles_admitted":False}))
