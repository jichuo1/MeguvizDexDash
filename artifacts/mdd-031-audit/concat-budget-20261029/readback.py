#!/usr/bin/env python3
"""Recheck executed concatenation budget regression and SQLite micro-oracle."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "artifacts/mdd-031-audit/concat-budget-20261029"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def identity(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def command(name, expected):
    path = BASE / name / "record.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    require(saved["exit_code"] == expected, name + " exit differs")
    for stream in ("stdout", "stderr"):
        require(identity(path.parent / (stream + ".txt")) == saved[stream], name + " " + stream + " changed")
    return {"path": path.relative_to(ROOT).as_posix(), **identity(path), "exit_code": expected}


def main():
    records = [command(name, code) for name, code in
               [("red", 101), ("green", 0), ("full", 0), ("clippy", 0), ("sqlite-reference", 0)]]
    red = (BASE / "red/stdout.txt").read_text(encoding="utf-8")
    require("running 2 tests" in red and red.count("called `Result::unwrap_err()` on an `Ok` value") == 2
            and red.count("calculation_complete: true") == 2, "actual red regression differs")
    for name in ("concat_long_bytes_respects_session_step_budget", "concat_long_text_respects_session_step_budget"):
        require(name + " ... FAILED" in red, "red case missing: " + name)
    green = (BASE / "green/stdout.txt").read_text(encoding="utf-8")
    full = (BASE / "full/stdout.txt").read_text(encoding="utf-8")
    require(re.search(r"test result: ok\. 5 passed; 0 failed; 0 ignored;", green) is not None,
            "targeted tests incomplete")
    require(re.search(r"test result: ok\. 73 passed; 0 failed; 0 ignored;", full) is not None
            and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", full) is not None,
            "SQL package tests incomplete")
    sqlite = json.loads((BASE / "sqlite-reference/stdout.txt").read_text(encoding="utf-8"))
    require(sqlite["text_utf16"] == [65, 0, 55357, 56832] and sqlite["null"] is None
            and sqlite["blob_concat_hex"] == "00FF41" and sqlite["blob_concat_type"] == "text",
            "SQLite micro-oracle differs")
    sources = {}
    for path in ("crates/mdd-sql/src/dialects/functions.rs", "crates/mdd-sql/src/runtime_tests.rs", "Cargo.lock"):
        sources[path] = identity(ROOT / path)["sha256"]
    print(json.dumps({"status": "passed-scoped", "records": records, "sources": sources,
                      "targeted_tests": 5, "unit_tests": 73, "compile_fail_tests": 1,
                      "sqlite_version": sqlite["sqlite_version"],
                      "scope": "concatenation output-copy steps and checked length arithmetic",
                      "limits": ["argument decoding and result/carrier buffers have no new workspace reservation",
                                 "SQLite allocation, allocator overhead and RSS are not covered",
                                 "SQLite blob concatenation is TEXT while bridge preserves its existing Bytes policy",
                                 "A0/A1 concatenation type and isolated-surrogate SQLite TEXT not newly tested",
                                 "precise instruction at asynchronous cancellation is not observable"],
                      "profile_admitted": False}))


if __name__ == "__main__":
    main()
