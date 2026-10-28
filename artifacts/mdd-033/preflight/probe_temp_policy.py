"""Tiny fixed-engine TEMP policy observation; no private input or engine qualification.

Reuses the already verified isolated mcp 2.2.0 Client and StdioServerParameters
pattern from MDD005 mcp_capability_probe/a2_compact_fixture_probe. One engine
process at a time; each scenario opens and closes its own 660-byte dataset.
"""
from pathlib import Path
import asyncio
import datetime
import hashlib
import importlib.metadata
import json
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
FIXTURE = ROOT / "tests/fixtures/references/generated/classic-035.dex"
FIXTURE_SHA = "076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8"

CASES = [
    ("table-if-not-exists", [
        "CREATE TEMP TABLE item AS SELECT 1 AS x",
        "CREATE TEMP TABLE IF NOT EXISTS item AS SELECT 2 AS x",
        "SELECT x FROM item",
        "CREATE TEMP TABLE IF NOT EXISTS item AS SELECT x FROM never_defined",
        "SELECT x FROM item"]),
    ("view-if-not-exists", [
        "CREATE TEMP VIEW item AS SELECT 1 AS x",
        "CREATE TEMP VIEW IF NOT EXISTS item AS SELECT 2 AS x",
        "SELECT x FROM item",
        "CREATE TEMP VIEW IF NOT EXISTS item AS SELECT x FROM never_defined",
        "SELECT x FROM item"]),
    ("table-drop-if-exists", [
        "DROP TABLE IF EXISTS absent",
        "DROP TABLE absent",
        "CREATE TEMP TABLE item AS SELECT 1 AS x",
        "DROP TABLE IF EXISTS item",
        "SELECT x FROM item",
        "DROP TABLE IF EXISTS item"]),
    ("view-drop-if-exists", [
        "DROP VIEW IF EXISTS absent",
        "DROP VIEW absent",
        "CREATE TEMP VIEW item AS SELECT 1 AS x",
        "DROP VIEW IF EXISTS item",
        "SELECT x FROM item",
        "DROP VIEW IF EXISTS item"]),
    ("table-then-view-same-name", [
        "CREATE TEMP TABLE item AS SELECT 1 AS x",
        "CREATE TEMP VIEW item AS SELECT 2 AS x",
        "SELECT x FROM item", "DROP TABLE item", "SELECT x FROM item"]),
    ("view-then-table-same-name", [
        "CREATE TEMP VIEW item AS SELECT 1 AS x",
        "CREATE TEMP TABLE item AS SELECT 2 AS x",
        "SELECT x FROM item", "DROP VIEW item", "SELECT x FROM item"]),
    ("table-then-view-if-not-exists", [
        "CREATE TEMP TABLE item AS SELECT 1 AS x",
        "CREATE TEMP VIEW IF NOT EXISTS item AS SELECT 2 AS x",
        "SELECT x FROM item", "DROP VIEW item", "SELECT x FROM item"]),
    ("view-then-table-if-not-exists", [
        "CREATE TEMP VIEW item AS SELECT 1 AS x",
        "CREATE TEMP TABLE IF NOT EXISTS item AS SELECT 2 AS x",
        "SELECT x FROM item", "DROP TABLE item", "SELECT x FROM item"]),
    ("drop-view-on-table", [
        "CREATE TEMP TABLE item AS SELECT 1 AS x", "DROP VIEW item", "SELECT x FROM item"]),
    ("drop-table-on-view", [
        "CREATE TEMP VIEW item AS SELECT 1 AS x", "DROP TABLE item", "SELECT x FROM item"]),
    ("drop-view-if-exists-on-table", [
        "CREATE TEMP TABLE item AS SELECT 1 AS x", "DROP VIEW IF EXISTS item", "SELECT x FROM item"]),
    ("drop-table-if-exists-on-view", [
        "CREATE TEMP VIEW item AS SELECT 1 AS x", "DROP TABLE IF EXISTS item", "SELECT x FROM item"]),
    ("forward-table", [
        "CREATE TEMP TABLE derived AS SELECT x FROM future",
        "SELECT x FROM derived",
        "CREATE TEMP TABLE future AS SELECT 7 AS x",
        "SELECT x FROM derived"]),
    ("forward-view", [
        "CREATE TEMP VIEW derived AS SELECT x FROM future",
        "SELECT x FROM derived",
        "CREATE TEMP VIEW future AS SELECT 7 AS x",
        "SELECT x FROM derived"]),
    ("forward-table-if-not-exists", [
        "CREATE TEMP TABLE IF NOT EXISTS derived AS SELECT x FROM future",
        "SELECT x FROM derived",
        "CREATE TEMP TABLE future AS SELECT 7 AS x",
        "SELECT x FROM derived"]),
    ("forward-view-if-not-exists", [
        "CREATE TEMP VIEW IF NOT EXISTS derived AS SELECT x FROM future",
        "SELECT x FROM derived",
        "CREATE TEMP VIEW future AS SELECT 7 AS x",
        "SELECT x FROM derived"]),
]

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()

def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

def body(response):
    # Match the existing standard (noncompact) MCP helper, preserving tool errors.
    raw = response.model_dump(mode="json", by_alias=True)
    structured = raw.get("structuredContent")
    text = "\n".join(item["text"] for item in raw.get("content", []) if item.get("type") == "text")
    if structured is not None:
        parsed = structured
    else:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = {"unparsed_text": text}
    return {"is_error": bool(raw.get("isError", False)), "body": parsed, "mcp_result": raw}

async def probe(variant, directory):
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters
    binary = Path(variant["engine_binary"]["path"]).resolve()
    require(binary.is_file() and digest(binary) == variant["engine_binary"]["sha256"], "fixed engine identity mismatch")
    args = ["--threads", "1", "mcp", "--timeout-ms", "1500", "--max-datasets", "1"]
    transcript_path = directory / (variant["id"] + ".sdk-transcript.jsonl")
    transcript = transcript_path.open("x", encoding="utf-8", newline="\n")
    params = StdioServerParameters(command=str(binary), args=args, cwd=ROOT)
    report = {"variant": variant["id"], "engine_path": str(binary), "engine_sha256": digest(binary), "engine_bytes": binary.stat().st_size, "command": [str(binary), *args], "cases": [], "active_dataset_after_all_cases": None}
    def record(value):
        transcript.write(json.dumps(value, ensure_ascii=True) + "\n")
        transcript.flush()
    async def call(client, name, arguments):
        record({"direction": "request", "tool": name, "arguments": arguments})
        async with asyncio.timeout(5):
            response = body(await client.call_tool(name, arguments))
        record({"direction": "response", "tool": name, "result": response})
        return response
    try:
        async with asyncio.timeout(45), Client(params, read_timeout_seconds=5) as client:
            report["server_info"] = client.server_info.model_dump(mode="json", by_alias=True)
            record({"kind": "initialized_server_info", "server_info": report["server_info"]})
            for name, statements in CASES:
                opened = await call(client, "open_dataset", {"inputs": [str(FIXTURE)]})
                require(not opened["is_error"], "tiny independent dataset failed to open")
                dataset = opened["body"]["dataset_id"]
                result = {"id": name, "dataset_id": dataset, "open": opened, "statements": []}
                report["cases"].append(result)
                try:
                    for ordinal, sql in enumerate(statements):
                        response = await call(client, "query", {"dataset_id": dataset, "sql": [sql], "limit": 10, "offset": 0})
                        result["statements"].append({"ordinal": ordinal, "sql": sql, "response": response})
                finally:
                    result["close"] = await call(client, "close_dataset", {"dataset_id": dataset})
                    require(not result["close"]["is_error"], "dataset close failed")
            remaining = await call(client, "list_datasets", {})
            report["active_dataset_after_all_cases"] = remaining
            require(not remaining["is_error"], "final dataset list failed")
        report["client_context_exited"] = True
        require(digest(binary) == report["engine_sha256"], "engine changed during observation")
        return report
    finally:
        transcript.close()
        report["transcript_sha256"] = digest(transcript_path)
        dump(directory / (variant["id"] + ".observations.json"), report)

async def main():
    require(importlib.metadata.version("mcp") == "2.2.0", "use the verified isolated MCP environment")
    require(FIXTURE.stat().st_size == 660 and digest(FIXTURE) == FIXTURE_SHA, "fixed tiny input identity mismatch")
    plan = json.loads((ROOT / "benchmarks/baseline-manifest.json").read_text(encoding="utf-8"))
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = OUT / stamp
    directory.mkdir(parents=True, exist_ok=False)
    results = []
    for name in ["A0", "A1"]:
        variant = next(item for item in plan["variants"] if item["id"] == name)
        results.append(await probe(variant, directory))
    require(digest(FIXTURE) == FIXTURE_SHA, "input changed during observation")
    report = {"schema_version": "mdd.temp-policy-preflight.v1", "task": "MDD-033", "status": "observations_recorded_not_qualified", "fixture": {"path": str(FIXTURE), "bytes": 660, "sha256": FIXTURE_SHA}, "mcp_version": importlib.metadata.version("mcp"), "python": sys.version, "driver_sha256": digest(Path(__file__).resolve()), "existing_helper_patterns": ["artifacts/mdd-005/preparation-20261028/mcp_capability_probe.py", "artifacts/mdd-005/preparation-20261028/a2_compact_fixture_probe.py"], "max_simultaneous_engine_processes": 1, "native_timeout_ms": 1500, "client_call_timeout_seconds": 5, "engine_session_timeout_seconds": 45, "formal_measurement": False, "private_input_parsed": False, "new_engine_executed": False, "profiles_admitted": False, "MDD033_done": False, "records": [{"variant": result["variant"], "cases": len(result["cases"]), "statements": sum(len(case["statements"]) for case in result["cases"]), "observations_path": (directory / (result["variant"] + ".observations.json")).relative_to(ROOT).as_posix(), "observations_sha256": digest(directory / (result["variant"] + ".observations.json"))} for result in results]}
    dump(directory / "summary.json", report)
    print(json.dumps({"summary": (directory / "summary.json").relative_to(ROOT).as_posix(), "records": report["records"], "MDD033_done": False}))

if __name__ == "__main__":
    asyncio.run(main())
