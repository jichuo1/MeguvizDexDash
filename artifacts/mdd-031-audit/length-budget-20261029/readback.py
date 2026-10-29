#!/usr/bin/env python3
"""Recheck the executed SQL length budget regression without signing a profile."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "artifacts/mdd-031-audit/length-budget-20261029"


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
    streams = {}
    for stream in ("stdout", "stderr"):
        streams[stream] = identity(folder / (stream + ".txt"))
        require(streams[stream] == saved[stream], name + " " + stream + " identity differs")
    return {"path": path.relative_to(ROOT).as_posix(), **identity(path), "exit_code": exit_code}


def main():
    records = [record(name, exit_code) for name, exit_code in
               [("red", 0), ("red-selected", 101), ("green", 0), ("full", 0), ("clippy", 0)]]
    first = (BASE / "red/stdout.txt").read_text(encoding="utf-8")
    failure = (BASE / "red-selected/stdout.txt").read_text(encoding="utf-8")
    green = (BASE / "green/stdout.txt").read_text(encoding="utf-8")
    full = (BASE / "full/stdout.txt").read_text(encoding="utf-8")
    require("running 0 tests" in first, "first exact filter must remain an unexecuted observation")
    require("running 1 test" in failure and "called `Result::unwrap_err()` on an `Ok` value" in failure
            and "Signed64(50000)" in failure and "DexSql010" in failure,
            "actual red regression differs")
    require(re.search(r"test result: ok\. 4 passed; 0 failed; 0 ignored;", green) is not None,
            "focused tests incomplete")
    require(re.search(r"test result: ok\. 46 passed; 0 failed; 0 ignored;", full) is not None
            and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", full) is not None,
            "SQL package tests incomplete")
    sources = {}
    for path in ("crates/mdd-sql/src/dialects/functions.rs", "crates/mdd-sql/src/runtime_tests.rs", "Cargo.lock"):
        sources[path] = identity(ROOT / path)["sha256"]
    print(json.dumps({"status": "passed-scoped", "records": records, "sources": sources,
                      "focused_tests": 4, "unit_tests": 46, "compile_fail_tests": 1,
                      "scope": "legacy length UTF-16 pair scan steps and cancellation; native constant-time length unchanged",
                      "limits": ["text/parameter copies, SQLite buffers and RSS are not covered",
                                 "A0 reference covers only supplementary character and embedded NUL microcases",
                                 "precise instruction at asynchronous cancellation is not observable"],
                      "profile_admitted": False}))


if __name__ == "__main__":
    main()
