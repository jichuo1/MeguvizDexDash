#!/usr/bin/env python3
"""Recheck recorded SQL grouping-key step regressions without granting a profile."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "artifacts/mdd-031-audit/key-scan-20261029"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def command(name, expected):
    folder = BASE / name
    path = folder / "record.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    require(saved["exit_code"] == expected, name + " exit differs")
    for stream in ("stdout", "stderr"):
        require(identity(folder / (stream + ".txt")) == saved[stream], name + " " + stream + " changed")
    return {"path": path.relative_to(ROOT).as_posix(), **identity(path), "exit_code": expected}


def main():
    records = [command(name, code) for name, code in
               [("red", 101), ("green", 0), ("green-expanded", 0), ("green-final", 0),
                ("full", 0), ("clippy", 0)]]
    red = (BASE / "red/stdout.txt").read_text(encoding="utf-8")
    for name in ("key_distinct_long_bytes", "key_distinct_long_text", "key_group_long_text", "key_order_long_text"):
        require(name + "_respects_session_step_budget ... FAILED" in red, "red case missing: " + name)
    require(red.count("called `Result::unwrap_err()` on an `Ok` value") == 4
            and red.count("calculation_complete: true") == 4, "red successful outcomes differ")
    green = (BASE / "green-final/stdout.txt").read_text(encoding="utf-8")
    full = (BASE / "full/stdout.txt").read_text(encoding="utf-8")
    require(re.search(r"test result: ok\. 6 passed; 0 failed; 0 ignored;", green) is not None,
            "targeted tests incomplete")
    require(re.search(r"test result: ok\. 59 passed; 0 failed; 0 ignored;", full) is not None
            and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", full) is not None,
            "SQL package tests incomplete")
    sources = {}
    for path in ("crates/mdd-sql/src/dialects/functions.rs", "crates/mdd-sql/src/runtime_tests.rs", "Cargo.lock"):
        sources[path] = identity(ROOT / path)["sha256"]
    print(json.dumps({"status": "passed-scoped", "records": records, "sources": sources,
                      "targeted_tests": 6, "unit_tests": 59, "compile_fail_tests": 1,
                      "scope": "UTF-16 and raw-byte key construction steps/cancellation in DISTINCT, GROUP and ORDER",
                      "limits": ["key Vec has no workspace reservation; no key workspace quota claim",
                                 "SQLite TRANSIENT copies and sorter lifetime are not accounted by this change",
                                 "input carriers, SQLite, allocator overhead and RSS are not covered",
                                 "precise instruction at asynchronous cancellation is not observable"],
                      "profile_admitted": False}))


if __name__ == "__main__":
    main()
