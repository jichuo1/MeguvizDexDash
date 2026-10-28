#!/usr/bin/env python3
"""Verify the immutable initial engineering handoff, not an engine implementation.

After intentional edits, the package hashes and initial task-state checks are
expected to change. This is not the future engine's CI or a release qualifier.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def reject_constant(value: str):
    raise ValueError("Non-JSON constant: " + value)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON key: " + key)
        value[key] = item
    return value


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"),
                      object_pairs_hook=unique_object, parse_constant=reject_constant)


def require(condition: bool, message: str):
    if not condition:
        raise ValueError(message)


def local_path(relative: str) -> Path:
    candidate = (ROOT / relative).resolve()
    require(candidate.is_relative_to(ROOT), "Path escapes kit: " + relative)
    return candidate


def verify_manifest() -> int:
    manifest = read_json(ROOT / "PACKAGE_MANIFEST.json")
    require(manifest["engine_implemented"] is False, "Package is not an initial handoff")
    names = set()
    for item in manifest["files"]:
        name = item["path"]
        require(name not in names, "Duplicate manifest entry: " + name)
        names.add(name)
        path = local_path(name)
        require(path.is_file(), "Missing manifest file: " + name)
        payload = path.read_bytes()
        require(len(payload) == item["bytes"], "File size changed: " + name)
        require(hashlib.sha256(payload).hexdigest() == item["sha256"],
                "File digest changed: " + name)
    actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
              if p.is_file() and "__pycache__" not in p.parts
              and p.name != "PACKAGE_MANIFEST.json"}
    require(actual == names, "Manifest does not exactly cover kit files")
    return len(names)


def verify_evidence() -> int:
    index = read_json(ROOT / "evidence/index.json")
    require(index["engine_implemented"] is False, "Historical evidence misclassified")
    seen = set()
    for item in index["files"]:
        require(item["id"] not in seen, "Duplicate evidence ID")
        seen.add(item["id"])
        path = local_path(item["path"])
        payload = path.read_bytes()
        require(len(payload) == item["bytes"], "Evidence size mismatch")
        require(hashlib.sha256(payload).hexdigest() == item["sha256"],
                "Evidence hash mismatch: " + item["path"])
    return len(seen)


def verify_tasks() -> int:
    backlog = read_json(ROOT / "tasks/backlog.json")
    require(backlog["implementation_state"] == "not_started", "Not an initial task snapshot")
    tasks = backlog["tasks"]
    expected = {f"MDD-{n:03d}" for lo, hi in
                [(1, 6), (10, 14), (20, 26), (30, 35), (40, 44),
                 (50, 55), (60, 65), (70, 75), (80, 83)]
                for n in range(lo, hi + 1)}
    by_id = {task["id"]: task for task in tasks}
    require(len(tasks) == 51 and len(by_id) == 51 and set(by_id) == expected,
            "Task IDs/count differ from initial M0–M8 specification")
    for task in tasks:
        require(task["status"] == "todo", "Initial task is not todo: " + task["id"])
        require(task["evidence_required"] is True, "Task lacks evidence requirement")
        for key in ("scope", "outputs", "acceptance", "references"):
            require(isinstance(task[key], list) and bool(task[key]),
                    "Empty task field: " + task["id"] + "." + key)
        require(bool(task["owner_role"]), "Task has no owner role")
        require(len(task["depends_on"]) == len(set(task["depends_on"])), "Repeated dependency")
        for dep in task["depends_on"]:
            require(dep in by_id and dep != task["id"], "Invalid dependency: " + dep)
        for ref in task["references"]:
            require(local_path(ref).exists(), "Missing task reference: " + ref)
    visiting, visited = set(), set()

    def visit(name):
        require(name not in visiting, "Cycle in task dependencies: " + name)
        if name in visited:
            return
        visiting.add(name)
        for dep in by_id[name]["depends_on"]:
            visit(dep)
        visiting.remove(name)
        visited.add(name)

    for name in by_id:
        visit(name)
    return len(tasks)


def verify_links() -> int:
    count = 0
    for path in ROOT.rglob("*.md"):
        content = path.read_text(encoding="utf-8")
        for target in re.findall(r"\[[^\]\n]*\]\(([^)\n]+)\)", content):
            target = target.split(' "', 1)[0].strip("<>")
            if urlparse(target).scheme or target.startswith("#"):
                continue
            relative = unquote(target.split("#", 1)[0])
            if not relative:
                continue
            destination = (path.parent / relative).resolve()
            require(destination.is_relative_to(ROOT),
                    "Non-portable local link: " + str(path) + " -> " + relative)
            require(destination.exists(), "Broken local link: " + str(path) + " -> " + relative)
            count += 1
    return count


def verify_initial_claims():
    ledger = read_json(ROOT / "compatibility/ledger.json")
    require(ledger["implementation_state"] == "not_started", "Unexpected implementation state")
    require(all(p["status"] == "planned" and p["admitted"] is False
                and not p["evidence"] for p in ledger["profiles"]), "Premature profile qualification")
    artifacts = read_json(ROOT / "artifacts/index.json")
    for key in ("engine_builds", "engine_runs", "conformance_manifests", "benchmark_runs", "qualifications"):
        require(artifacts[key] == [], "Initial handoff contains a claimed new-engine result")
    workloads = read_json(ROOT / "benchmarks/workloads/initial.json")
    require(workloads["measured_runs"] == [], "Planned workloads contain measurements")
    require({w["id"] for w in workloads["workloads"]} == {f"W{i:02d}" for i in range(1, 13)},
            "Workload IDs differ from validation plan")


def verify_schemas(required: bool) -> str:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError:
        if required:
            raise ValueError("jsonschema unavailable: required schema validation did not run")
        return "NOT RUN: jsonschema is not installed; JSON syntax was checked only"
    validators = {}
    for name in ("result", "capabilities", "benchmark_result"):
        schema = read_json(ROOT / f"contracts/{name}.schema.json")
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(schema, format_checker=FormatChecker())
    examples = list((ROOT / "contracts/examples").glob("*.example.json"))
    for path in examples:
        kind = "capabilities" if path.name.startswith("capabilities") else "result"
        validators[kind].validate(read_json(path))
    complete = read_json(ROOT / "contracts/examples/result_complete.example.json")
    page = read_json(ROOT / "contracts/examples/result_page.example.json")
    error = read_json(ROOT / "contracts/examples/result_error.example.json")
    caps = read_json(ROOT / "contracts/examples/capabilities_unqualified.example.json")
    # Contract-only negative fixtures, not measurements or engine responses.
    invalid = []
    x = copy.deepcopy(complete); x.pop("coverage"); invalid.append(("result", x))
    x = copy.deepcopy(complete); x["catalog_epoch"] = 0; invalid.append(("result", x))
    x = copy.deepcopy(complete); x["response"]["total_rows"] = None; invalid.append(("result", x))
    x = copy.deepcopy(complete); x["error"] = error["error"]; invalid.append(("result", x))
    x = copy.deepcopy(page); x["response"]["next_cursor"] = None; invalid.append(("result", x))
    x = copy.deepcopy(error); x["operation_status"] = "cancelled"; invalid.append(("result", x))
    x = copy.deepcopy(caps); x["profiles"][0]["admitted"] = True; invalid.append(("capabilities", x))
    x = copy.deepcopy(caps); x["transports"][0]["result_encodings"] = ["binary"]; invalid.append(("capabilities", x))
    for kind, specimen in invalid:
        require(not validators[kind].is_valid(specimen), "Invalid contract fixture was accepted")
    # Cancellation after complete calculation is legal, but never audit success.
    for computation_finished in (False, True):
        cancelled = copy.deepcopy(error)
        cancelled["operation_status"] = "cancelled"
        cancelled["error"]["code"] = "CANCELLED"
        cancelled["execution"]["complete"] = computation_finished
        validators["result"].validate(cancelled)
    return f"3 Draft 2020-12 schemas; {len(examples)} examples; {len(invalid)} rejected negative fixtures; 2 cancellation states"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-schema", action="store_true",
                        help="Fail if the independent jsonschema validator is missing")
    args = parser.parse_args()
    try:
        manifest_files = verify_manifest()
        json_files = list(ROOT.rglob("*.json"))
        for path in json_files:
            read_json(path)
        evidence = verify_evidence()
        tasks = verify_tasks()
        links = verify_links()
        verify_initial_claims()
        schemas = verify_schemas(args.require_schema)
        print(f"PACKAGE VERIFIED: {manifest_files} hashed files; {len(json_files)} JSON files; "
              f"{evidence} historical evidence files; {tasks} acyclic todo tasks; {links} local links")
        print("SCHEMA VALIDATION: " + schemas)
        print("SCOPE: engineering handoff only. No MeguvizDexDash engine was built, executed, benchmarked or qualified.")
        return 0
    except (ValueError, KeyError, OSError, TypeError) as exc:
        print("PACKAGE VERIFICATION FAILED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
