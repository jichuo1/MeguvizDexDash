#!/usr/bin/env python3
"""Failure controls for the readback inventory; does not issue a task gate."""
import copy
import json
import audit_columns as audit


def expect_failure(action, text):
    try:
        action()
    except ValueError as exc:
        if text in str(exc):
            return
        raise RuntimeError("unexpected failure: " + str(exc)) from exc
    raise RuntimeError("negative control did not fail: " + text)


def main():
    report = json.loads(audit.OUTPUT.read_text(encoding="utf-8"))
    summary = report["summary"]
    if summary != {"required_relations": 17, "required_columns": 156,
                   "relations_with_nonempty_full_row_multiset_comparison": 8,
                   "relations_without_such_comparison": 9, "unassembled_projection_columns": 69,
                   "required_columns_in_historical_a0_metadata_comparison": 40,
                   "required_columns_in_new_definition_api_comparison": 21}:
        raise RuntimeError("unexpected audit summary")
    if report["task_complete_proven"] or report["is_task_gate"]:
        raise RuntimeError("inventory must not claim completion")
    original_read = audit.read
    original_identity = audit.identity
    original_output = audit.OUTPUT.read_bytes()
    def bad_matrix(path):
        value = original_read(path)
        if path == "conformance/facts/required-columns.json":
            value = copy.deepcopy(value)
            value["column_count"] -= 1
        return value
    audit.read = bad_matrix
    expect_failure(audit.main, "column denominator mismatch")
    audit.read = original_read
    def bad_hash(path):
        value = original_identity(path)
        if path == "artifacts/mdd-026/final/differential/stdout.txt":
            value["sha256"] = "0" * 64
        return value
    audit.identity = bad_hash
    expect_failure(audit.main, "differential output drift")
    audit.identity = original_identity
    if audit.OUTPUT.read_bytes() != original_output:
        raise RuntimeError("failed audit overwrote successful report")
    print("2 negative controls passed; prior report retained")


if __name__ == "__main__":
    main()
