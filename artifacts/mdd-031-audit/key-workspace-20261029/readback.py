#!/usr/bin/env python3
"""Read back key workspace regressions and callback lifetime without profile admission."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "artifacts/mdd-031-audit/key-workspace-20261029"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


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
    for name in ("distinct_text", "distinct_bytes", "group_text", "order_text"):
        require("key_workspace_" + name + "_respects_budget ... FAILED" in red, "red case missing: " + name)
    require(red.count("called `Result::unwrap_err()` on an `Ok` value") == 4
            and red.count("calculation_complete: true") == 4, "red successful outcomes differ")
    green = (BASE / "green-final/stdout.txt").read_text(encoding="utf-8")
    full = (BASE / "full/stdout.txt").read_text(encoding="utf-8")
    for test in ("key_lease_survives_actual_rusqlite_to_sql_callback",
                 "key_workspace_checked_amount_rejects_overflow",
                 "key_workspace_cancellation_releases_temporary_lease",
                 "key_workspace_precancel_remains_cancelled_before_quota",
                 "key_workspace_releases_temporary_lease_after_success_and_result_drop"):
        require(test + " ... ok" in green, "missing test " + test)
    require(re.search(r"test result: ok\. 15 passed; 0 failed; 0 ignored;", green) is not None,
            "targeted tests incomplete")
    require(re.search(r"test result: ok\. 68 passed; 0 failed; 0 ignored;", full) is not None
            and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", full) is not None,
            "SQL package tests incomplete")
    sources = {}
    for path in ("crates/mdd-sql/src/dialects/functions.rs", "crates/mdd-sql/src/runtime_tests.rs",
                 "crates/mdd-sql/src/values.rs", "Cargo.lock"):
        sources[path] = identity(ROOT / path)["sha256"]
    print(json.dumps({"status": "passed-scoped", "records": records, "sources": sources,
                      "targeted_tests": 15, "unit_tests": 68, "compile_fail_tests": 1,
                      "scope": "logical capacity reservation for Rust key and carrier until rusqlite callback returns",
                      "callback_lifetime": "actual SQLite callback observed live lease at ToSql; fixed rusqlite source keeps returned object through SQLITE_TRANSIENT copy call",
                      "limits": ["SQLite TRANSIENT copy and sorter lifetime are not charged by this lease",
                                 "input/argument carriers and clones, allocator overhead and RSS are not covered",
                                 "precise instruction at asynchronous cancellation is not observable"],
                      "profile_admitted": False}))


if __name__ == "__main__":
    main()
