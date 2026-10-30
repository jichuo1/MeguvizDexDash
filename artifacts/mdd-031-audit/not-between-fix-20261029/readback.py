#!/usr/bin/env python3
"""Read back NOT BETWEEN regression evidence; do not grant a SQL profile."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "artifacts/mdd-031-audit/not-between-fix-20261029"


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
    require(saved["exit_code"] == expected, name + " exit code differs")
    for stream in ("stdout", "stderr"):
        require(identity(folder / (stream + ".txt")) == saved[stream], name + " " + stream + " changed")
    return {"path": path.relative_to(ROOT).as_posix(), **identity(path), "exit_code": expected}


def main():
    records = [command(name, code) for name, code in
               [("red", 101), ("red-expanded", 101), ("green", 0), ("full", 0), ("clippy", 0)]]
    red = (BASE / "red-expanded/stdout.txt").read_text(encoding="utf-8")
    require("running 1 test" in red and "NOT mdd_ge(id, ?1) AND mdd_le(id, ?2)" in red
            and "left: []" in red and "right: [[U64(DecimalU64(3))]]" in red,
            "original precedence failure differs")
    green = (BASE / "green/stdout.txt").read_text(encoding="utf-8")
    full = (BASE / "full/stdout.txt").read_text(encoding="utf-8")
    require(re.search(r"test result: ok\. 2 passed; 0 failed; 0 ignored;", green) is not None,
            "targeted tests incomplete")
    require(re.search(r"test result: ok\. 53 passed; 0 failed; 0 ignored;", full) is not None
            and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", full) is not None,
            "package tests incomplete")
    reference = ROOT / "artifacts/mdd-031-audit/between-independent-20261029/sqlite-reference/stdout.txt"
    sqlite = json.loads(reference.read_text(encoding="utf-8"))
    require(sqlite["samples"]["not_between"]["rows"] == [[-1], [9]], "SQLite reference differs")
    sources = {}
    for path in ("crates/mdd-sql/src/dialects/ast.rs", "crates/mdd-sql/src/bridge.rs",
                 "crates/mdd-sql/src/dialects/functions.rs", "crates/mdd-sql/src/runtime_tests.rs", "Cargo.lock"):
        sources[path] = identity(ROOT / path)["sha256"]
    print(json.dumps({"status": "passed-scoped", "records": records, "sources": sources,
                      "sqlite_reference": {"path": reference.relative_to(ROOT).as_posix(), **identity(reference),
                                           "version": sqlite["sqlite_version"]},
                      "targeted_tests": 2, "unit_tests": 53, "compile_fail_tests": 1,
                      "scope": "NOT grouping, three-valued NULL, inclusive boundaries and duplicates",
                      "limits": ["A0/A1 not newly run", "mixed textual boundary affinity remains unqualified",
                                 "synthetic facts only; full required SQL/profile not qualified"],
                      "profile_admitted": False}))


if __name__ == "__main__":
    main()
