#!/usr/bin/env python3
"""Recheck executed HEX budget regression records without signing a profile."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "artifacts/mdd-031-audit/hex-budget-20261029"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def identity(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def record(name, exit_code):
    folder = BASE / name
    path = folder / "record.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    require(saved["exit_code"] == exit_code, name + " exit status differs")
    for stream in ("stdout", "stderr"):
        require(identity(folder / (stream + ".txt")) == saved[stream], name + " " + stream + " differs")
    return {"path": path.relative_to(ROOT).as_posix(), **identity(path), "exit_code": exit_code}


def main():
    records = [record(name, code) for name, code in
               [("red-bytes", 101), ("red-text", 101), ("green-hex", 0),
                ("green-cast", 0), ("full", 0), ("clippy", 0)]]
    for name in ("red-bytes", "red-text"):
        output = (BASE / name / "stdout.txt").read_text(encoding="utf-8")
        require("running 1 test" in output and "called `Result::unwrap_err()` on an `Ok` value" in output
                and "calculation_complete: true" in output, name + " did not reproduce")
    green = (BASE / "green-hex/stdout.txt").read_text(encoding="utf-8")
    cast = (BASE / "green-cast/stdout.txt").read_text(encoding="utf-8")
    full = (BASE / "full/stdout.txt").read_text(encoding="utf-8")
    require(re.search(r"test result: ok\. 4 passed; 0 failed; 0 ignored;", green) is not None,
            "HEX tests incomplete")
    require(re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", cast) is not None,
            "CAST test incomplete")
    require(re.search(r"test result: ok\. 51 passed; 0 failed; 0 ignored;", full) is not None
            and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", full) is not None,
            "SQL package tests incomplete")
    sources = {}
    for path in ("crates/mdd-sql/src/dialects/functions.rs", "crates/mdd-sql/src/runtime_tests.rs", "Cargo.lock"):
        sources[path] = identity(ROOT / path)["sha256"]
    print(json.dumps({"status": "passed-scoped", "records": records, "sources": sources,
                      "hex_tests": 4, "cast_test": 1, "unit_tests": 51, "compile_fail_tests": 1,
                      "scope": "HEX byte output and shared text-to-bytes encoding steps and cancellation",
                      "limits": ["text/parameter copies, output buffers, SQLite buffers and RSS not covered",
                                 "prior A0/A1 text samples retained; no new old-engine run",
                                 "precise instruction at asynchronous cancellation is not observable"],
                      "profile_admitted": False}))


if __name__ == "__main__":
    main()
