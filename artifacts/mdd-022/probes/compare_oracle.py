#!/usr/bin/env python3
"""Compare complete tiny reference relations against the independent byte oracle."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def statement_rows(result):
    require("tool_error" not in result, "reference tool error")
    require(len(result["statements"]) == 1, "reference statement count")
    statement = result["statements"][0]
    require(statement["kind"] == "query" and not statement["truncated"] and statement["next_offset"] is None, "reference not fully delivered")
    columns = [column["name"] for column in statement["columns"]]
    rows = []
    for raw in statement["rows"]:
        require(len(raw) == len(columns), "reference row width")
        row = {}
        for name, cell in zip(columns, raw):
            kind, value = cell["type"], cell["value"]
            if kind in ["uint64", "int64"]:
                require(isinstance(value, str), "reference int64 precision encoding changed")
                number = int(value)
                if name != "value_i64":
                    require(0 <= number <= 0xffffffff, "frozen UInt32 projection overflow")
                    value = number
                else:
                    value = str(number)
            elif kind == "float64" and isinstance(value, str):
                require(value in ["NaN", "Infinity", "-Infinity"], "unknown nonfinite float encoding")
            elif kind == "null":
                require(value is None, "NULL encoding changed")
            row[name] = value
        rows.append(row)
    return columns, rows


def main():
    reference_path = HERE / "reference-results.json"
    reference = json.loads(reference_path.read_text())
    oracle_path = ROOT / "tests/fixtures/annotations/oracle-results.json"
    oracle = json.loads(oracle_path.read_text())
    require(reference["success"] and oracle["success"], "missing successful reference or independent oracle")
    positive = ROOT / "tests/fixtures/annotations/generated/annotations-038.dex"
    require(reference["input"]["sha256"] == hashlib.sha256(positive.read_bytes()).hexdigest(), "reference/oracle input identity changed")
    require(reference["process_exit_code"] == 0, "reference process did not finish successfully")
    labels = {"directories":"annotation_directories", "directory_entries":"annotation_directory_entries", "set_entries":"annotation_set_entries",
              "set_refs":"annotation_set_refs", "annotations":"annotations", "elements":"annotation_elements"}
    comparisons = []
    normalized = {}
    for query in reference["query_results"]:
        if query["label"] not in labels:
            continue
        relation = labels[query["label"]]
        columns, actual = statement_rows(query["result"])
        expected = oracle["positive"][relation]
        actual_rows = sorted(map(canonical, actual))
        expected_rows = sorted(map(canonical, expected))
        same = actual_rows == expected_rows
        comparisons.append({"relation":relation,"columns":columns,"reference_rows":len(actual),"oracle_rows":len(expected),"equal_multiset":same,
            "reference_sha256":hashlib.sha256("\n".join(actual_rows).encode()).hexdigest(),
            "oracle_sha256":hashlib.sha256("\n".join(expected_rows).encode()).hexdigest(),
            "first_difference":next((pair for pair in zip(actual_rows,expected_rows) if pair[0] != pair[1]),None)})
        normalized[relation] = actual
    require(len(comparisons) == 6 and all(item["equal_multiset"] for item in comparisons), "annotation reference/oracle difference")
    elements = normalized["annotation_elements"]
    nested = [row for row in elements if row["annotation_off"] == 1012 and row["depth"] == 1]
    report = {"schema_version":"mdd.annotation-reference-comparison.v1","success":True,"comparisons":comparisons,"normalized_reference_rows":normalized,
        "reference_result_sha256":hashlib.sha256(reference_path.read_bytes()).hexdigest(),"oracle_result_sha256":hashlib.sha256(oracle_path.read_bytes()).hexdigest(),
        "observations":[
            "annotation_directory_entries excludes the class annotation set; class_annotations_off is in annotation_directories.",
            "entry_kind is singular parameter and entry_idx is method_idx; annotation_set_off is NULL while annotation_set_ref_list_off identifies its ordered parameter slots.",
            "Top-level annotation elements have depth0; array/nested annotation children have depth1. ordinal resets per sibling sequence, not a global preorder ID.",
            "Array children have name_idx NULL; nested named annotation children retain their own name_idx. Both can share depth/ordinal inside one root annotation.",
            "value_off includes encoded_value tag byte; value_end_off excludes the end and spans complete child payloads for containers.",
            "Boolean projects integer0/1, annotation-valued node projects its type_idx in value_index, long values retain exact decimal strings.",
            "Nonfinite float64 MCP cells use tagged type=float64 with value string NaN/Infinity; negative-zero remains -0.0. The projection does not retain NaN payload bits, which the native oracle separately retains.",
            "Frozen UInt32 relation columns project as uint64 typed cells in observed MCP; every observed value was range-checked before comparison."
        ],
        "duplicate_depth_ordinal_example":nested,
        "scope":"Complete tiny synthetic relation comparison on A0 Windows0.1.0 only. No production annotation implementation, complete compatibility profile, HostLab qualification or performance claim."}
    (HERE / "oracle-comparison.json").write_text(json.dumps(report,indent=2,allow_nan=False)+"\n",encoding="utf-8")
    print("six complete annotation relations match independent oracle; " + ", ".join(item["relation"]+"="+str(item["reference_rows"]) for item in comparisons))


if __name__ == "__main__":
    main()
