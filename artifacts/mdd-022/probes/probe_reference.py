#!/usr/bin/env python3
"""Bounded read-only A0 MCP probes over synthetic annotation fixtures only."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
INPUT = ROOT / "tests/fixtures/annotations/generated/annotations-038.dex"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_json(text):
    def reject(value):
        raise ValueError("non-JSON constant: " + value)
    return json.loads(text, parse_constant=reject)


class Probe:
    def __init__(self, binary):
        self.records, self.stderr, self.pending = [], [], queue.Queue()
        self.process = subprocess.Popen([str(binary), "--threads", "1", "mcp"], cwd=HERE,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        def read_stdout():
            while True:
                line = self.process.stdout.readline(4 * 1024 * 1024)
                if not line:
                    self.pending.put(None)
                    return
                self.pending.put(line)

        def read_stderr():
            total = 0
            while True:
                value = self.process.stderr.read(4096)
                if not value:
                    return
                total += len(value)
                if total <= 131072:
                    self.stderr.append(value.decode("utf-8", "replace"))

        threading.Thread(target=read_stdout, daemon=True).start()
        threading.Thread(target=read_stderr, daemon=True).start()
        self.next_id = 1

    def send(self, method, params, notification=False):
        request = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            request["id"] = self.next_id
            self.next_id += 1
        self.records.append({"direction": "request", "message": request})
        self.process.stdin.write((json.dumps(request, allow_nan=False) + "\n").encode())
        self.process.stdin.flush()
        if notification:
            return None
        deadline = time.monotonic() + 30
        while True:
            line = self.pending.get(timeout=max(0.001, deadline - time.monotonic()))
            require(line is not None, "MCP stdout ended before response")
            text = line.decode("utf-8", "strict")
            response = strict_json(text)
            self.records.append({"direction": "response", "message": response})
            if response.get("id") == request["id"]:
                require("error" not in response, "JSONRPC error: " + json.dumps(response.get("error")))
                return response["result"]
            require(time.monotonic() < deadline, "MCP response deadline")

    def call(self, name, arguments):
        result = self.send("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            return {"tool_error": result}
        if "structuredContent" in result:
            return result["structuredContent"]
        text = next(block["text"] for block in result.get("content", []) if block.get("type") == "text")
        return strict_json(text)

    def close(self):
        try:
            if self.process.stdin:
                self.process.stdin.close()
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(self.process.pid), "/T", "/F"], capture_output=True, check=False)
            else:
                self.process.kill()
            self.process.wait(timeout=5)


def main():
    binaries = strict_json((ROOT / "conformance/manifests/engine-binaries.json").read_text())
    record = next(item for item in binaries["binaries"] if item["version"] == "0.1.0" and item["platform"] == "windows_amd64")
    binary = Path(record["actual_path"])
    actual_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    require(actual_sha == record["expected_sha256"], "reference binary identity mismatch")
    require(INPUT.resolve().is_relative_to((ROOT / "tests/fixtures/annotations").resolve()), "input escapes synthetic fixture folder")
    input_sha = hashlib.sha256(INPUT.read_bytes()).hexdigest()
    probe = Probe(binary)
    results, failure = [], None
    dataset = None
    try:
        initialization = probe.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mdd-022-annotation-probe", "version": "1"}})
        require(initialization["serverInfo"]["version"] == "0.1.0", "reference server version mismatch")
        probe.send("notifications/initialized", {}, notification=True)
        opened = probe.call("open_dataset", {"inputs": [str(INPUT)]})
        require("tool_error" not in opened, "open_dataset rejected synthetic input")
        dataset = opened["dataset_id"]
        queries = [
            ("identity", "SELECT file_id,entry_name,string_pool_id FROM dex_files ORDER BY file_id"),
            ("directories", "SELECT * FROM annotation_directories ORDER BY file_id,class_idx"),
            ("directory_entries", "SELECT * FROM annotation_directory_entries ORDER BY file_id,class_idx,entry_kind,entry_idx"),
            ("set_entries", "SELECT * FROM annotation_set_entries ORDER BY file_id,annotation_set_off,ordinal"),
            ("set_refs", "SELECT * FROM annotation_set_refs ORDER BY file_id,annotation_set_ref_list_off,ordinal"),
            ("annotations", "SELECT * FROM annotations ORDER BY file_id,annotation_off"),
            ("elements", "SELECT * FROM annotation_elements ORDER BY file_id,annotation_off,ordinal"),
        ]
        for label, sql in queries:
            value = probe.call("query", {"dataset_id": dataset, "sql": [sql], "limit": 1000})
            results.append({"label": label, "sql": sql, "result": value})
        probe.call("close_dataset", {"dataset_id": dataset})
        dataset = None
    except Exception as error:
        failure = {"type": type(error).__name__, "message": str(error)}
    finally:
        if dataset:
            try:
                probe.call("close_dataset", {"dataset_id": dataset})
            except Exception as error:
                probe.records.append({"close_error": str(error)})
        probe.close()
    tool_errors = [item["label"] for item in results if "tool_error" in item["result"]]
    report = {"schema_version": "mdd.annotation-reference-probes.v1", "time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "reference": {"path": str(binary), "sha256": actual_sha, "bytes": binary.stat().st_size, "version": "0.1.0", "platform": "windows_amd64"},
        "input": {"path": INPUT.relative_to(ROOT).as_posix(), "sha256": input_sha, "bytes": INPUT.stat().st_size},
        "protocol": "newline JSONRPC MCP, strict legal JSON parser", "records": probe.records, "query_results": results,
        "stderr": "".join(probe.stderr), "process_exit_code": probe.process.returncode,
        "failure": failure, "tool_error_queries": tool_errors, "success": failure is None and not tool_errors,
        "scope": "read-only compatibility observations on a synthetic annotated DEX only; not a performance trial, production parser, HostLab or release qualification"}
    output = HERE / "reference-results.json"
    if output.exists():
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        output = HERE / ("reference-results-" + stamp + ".json")
    with output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + "\n")
    print(f"reference annotation probe success={report['success']}; queries={len(results)}; failure={failure}; saved={output.name}")
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
