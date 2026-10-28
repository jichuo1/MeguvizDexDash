#!/usr/bin/env python3
"""Audit what the existing tiny fact differential actually demonstrates.

This is an evidence inventory, not a new independent parser or a task gate.
It checks original receipts and records observations without upgrading their
scope: multiset comparison is not an ordering check, and file_id=0 is supplied
by the probe rather than independently verified across sources.
"""
from __future__ import annotations

import collections
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "artifacts/mdd-026/new-audit/column-evidence.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def identity(path):
    data = (ROOT / path).read_bytes()
    return {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def stable(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def main():
    matrix_path = "conformance/facts/required-columns.json"
    differential_path = "artifacts/mdd-026/facts-differential.json"
    inputs_path = "artifacts/mdd-026/probe-inputs.json"
    matrix = read(matrix_path)
    differential = read(differential_path)
    inputs = read(inputs_path)
    old = read("artifacts/mdd-021/reference-comparison.json")
    reuse = read("artifacts/mdd-021/reference-evidence-reuse.json")
    old_native = read("artifacts/mdd-021/final-orphan-validation/observed-rust-definitions.json")
    require(hashlib.sha256(stable(old_native).encode("utf-8")).hexdigest() == reuse["canonical_facts_sha256"]
            and reuse["equal_typed_facts"], "historical typed-facts reuse identity differs")
    require(old["fixture_sha256"] == reuse["fixture_sha256"], "historical fixture identity differs")
    historical_columns = {}
    for comparison in old["comparisons"]:
        require(comparison["exit_code"] == 0 and comparison["equal_multiset"], "historical A0 comparison failed")
        def text_row(row):
            return {key: None if value is None else str(value) for key, value in row.items()}
        expected = collections.Counter(stable(text_row(row)) for row in comparison["expected"])
        observed = collections.Counter(stable(row) for row in comparison["observed"])
        require(expected == observed and sum(expected.values()) == comparison["expected_rows"]
                == comparison["observed_rows"], "historical A0 rows differ")
        historical_columns[comparison["relation"]] = set(comparison["columns"])
    new_path = "artifacts/mdd-026/new-audit/definition-projections/result.json"
    new_readback_path = "artifacts/mdd-026/new-audit/definition-projections/readback.json"
    new = read(new_path)
    new_readback = read(new_readback_path)
    require(new_readback["status"] == "passed" and new_readback["result_sha256"] == identity(new_path)["sha256"]
            and not new["task_complete_proven"], "new definition projection readback mismatch")
    new_columns = {item["relation"]: set(item["columns"]) for item in new["results"]}
    relations = {relation["name"]: relation for relation in matrix["relations"]}
    require(len(relations) == matrix["relation_count"] == 17, "relation denominator mismatch")
    require(sum(len(r["columns"]) for r in relations.values()) == matrix["column_count"] == 156,
            "column denominator mismatch")
    comparison_receipt = read("artifacts/mdd-026/final/differential/record.json")
    require(comparison_receipt["exit_code"] == 0, "differential command failed")
    require(identity("artifacts/mdd-026/final/differential/stdout.txt")["sha256"]
            == comparison_receipt["stdout_sha256"], "differential output drift")
    require(identity("artifacts/mdd-026/final/differential/stderr.txt")["sha256"]
            == comparison_receipt["stderr_sha256"], "differential error output drift")
    comparisons = collections.Counter((item["case"], item["relation"], item["rows"])
                                      for item in differential["complete_relation_comparisons"]
                                      if item["complete_multiset_equal"] is True)
    require(sum(comparisons.values()) == len(differential["complete_relation_comparisons"]),
            "comparison failed or incomplete")
    rows_by_relation = collections.defaultdict(list)
    duplicates_by_relation = collections.Counter()
    records = []
    reference_names = {"method_strings", "method_calls", "method_field_accesses", "method_used_types"}
    for case in inputs["cases"]:
        path = case["native_record"]
        receipt_path = str(Path(path).parent / "record.json").replace("\\", "/")
        receipt = read(receipt_path)
        require(receipt["exit_code"] == 0, "probe failed: " + case["case"])
        require(identity(path)["sha256"] == receipt["stdout_sha256"], "probe output drift: " + path)
        stderr = str(Path(path).parent / "stderr.txt").replace("\\", "/")
        require(identity(stderr)["sha256"] == receipt["stderr_sha256"], "probe stderr drift: " + stderr)
        output = read(path)
        require(output["probe_complete"] and output["operation_status"] == "ok", "probe not complete")
        require(len(output["dex_occurrences"]) == len(case["inputs"]), "occurrence mismatch")
        for sample in case["inputs"]:
            require(identity(sample["path"])["sha256"] == sample["sha256"], "fixture changed")
        records.extend([identity(path), identity(receipt_path), identity(stderr)])
        for occurrence in output["dex_occurrences"]:
            candidates = dict(occurrence["references"])
            strings = candidates["method_strings"]
            if strings["operation_status"] == "ok":
                candidates["method_strings"] = strings["rows"]
            else:
                candidates.pop("method_strings")
            annotation = occurrence["annotations"]
            if annotation["operation_status"] == "ok" and case["case"] in {"annotations", "parameter-positions-unknown"}:
                candidates.update(annotation["rows"])
            for name, relation_rows in candidates.items():
                if name not in relations or not isinstance(relation_rows, list):
                    continue
                key = (case["case"], name, len(relation_rows))
                if not comparisons[key]:
                    continue
                comparisons[key] -= 1
                fields = {c["name"] for c in relations[name]["columns"]}
                for row in relation_rows:
                    require(set(row) == fields, "row field set differs: " + name)
                occurrence_counts = collections.Counter(stable(row) for row in relation_rows)
                duplicates_by_relation[name] += sum(count - 1 for count in occurrence_counts.values())
                rows_by_relation[name].extend(relation_rows)
    require(not any(comparisons.values()), "a reported comparison could not be matched to original rows")

    report_relations = []
    for name, relation in relations.items():
        rows = rows_by_relation[name]
        columns = []
        for column in relation["columns"]:
            values = [row[column["name"]] for row in rows]
            columns.append({
                "ordinal": column["ordinal"], "name": column["name"],
                "data_type": column["data_type"], "nullable": column["nullable"],
                "production_projection": column["production_projection"],
                "full_relation_multiset_compared_on_nonempty_rows": bool(rows),
                "historical_a0_metadata_projection_compared": column["name"] in historical_columns.get(name, set()),
                "new_real_definition_row_api_a0_compared": column["name"] in new_columns.get(name, set()),
                "sample_value_count": len(values), "sample_null_count": sum(v is None for v in values),
                "sample_non_null_distinct_count": len({stable(v) for v in values if v is not None}),
                "source_identity_bound_in_complete_row_comparison": False if column["name"] in {"file_id", "string_pool_id"} else None,
                "next_check": ("independent full-row field/type/NULL/multiplicity comparison and source binding"
                               if not rows else "boundary values, source mapping and required ordering remain separate checks"),
            })
        report_relations.append({"name": name, "compared_nonempty_rows": len(rows),
                                 "duplicate_complete_rows_observed_within_occurrences": duplicates_by_relation[name],
                                 "order_proven_by_multiset_comparison": False, "columns": columns})

    unassembled = sum(c["production_projection"] == "unassembled_production_relation"
                      for relation in report_relations for c in relation["columns"])
    compared = [r for r in report_relations if r["compared_nonempty_rows"]]
    require(unassembled == 69 and len(compared) == 8, "unexpected current evidence inventory; review changes")
    report = {
        "schema_version": "mdd.column-evidence-audit.v1", "created_utc": datetime.now(timezone.utc).isoformat(),
        "task": "MDD-026", "is_task_gate": False, "task_complete_proven": False,
        "basis": "Readback of successful recorded tiny probe and differential; no new parser comparison performed",
        "relations": report_relations,
        "summary": {"required_relations": 17, "required_columns": 156,
                    "relations_with_nonempty_full_row_multiset_comparison": len(compared),
                    "relations_without_such_comparison": 17 - len(compared),
                    "unassembled_projection_columns": unassembled,
                    "required_columns_in_historical_a0_metadata_comparison": sum(
                        c["historical_a0_metadata_projection_compared"] for r in report_relations for c in r["columns"]),
                    "required_columns_in_new_definition_api_comparison": sum(
                        c["new_real_definition_row_api_a0_compared"] for r in report_relations for c in r["columns"])},
        "limitations": [
            "A complete relation comparison uses multisets and does not itself verify row order.",
            "The probe supplies file_id 0 for each occurrence; it does not compare real catalog assignment to A0.",
            "Observed null and duplicate counts describe samples only, not completeness of boundary coverage.",
            "Relations without a complete-row comparison may still have individual native-atom checks; this audit does not classify those as absent.",
            "SelectedScope now has a sequential file_id assigner, but projection and A0 identity equivalence remain unproven.",
            "The differential source was read for interpretation; historical source identity was not recorded by that receipt.",
            "Historical A0 metadata comparison reuses a previously recorded typed fact identity; it is not a new execution.",
            "The new API comparison checks A0 single-input rows and a second source rebound to file_id 1, not A0 multi-input equality.",
        ],
        "evidence": [identity(p) for p in [matrix_path, differential_path, inputs_path,
                     "conformance/facts/verify.py", "conformance/facts/native_probe.rs",
                     "artifacts/mdd-021/reference-comparison.json", "artifacts/mdd-021/reference-evidence-reuse.json",
                     "artifacts/mdd-021/final-orphan-validation/observed-rust-definitions.json", new_path, new_readback_path,
                     "crates/mdd-facts/src/indexes/scope.rs", "artifacts/mdd-026/final/differential/record.json",
                     "artifacts/mdd-026/final/differential/stdout.txt", "artifacts/mdd-026/final/differential/stderr.txt"]] + records,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report["summary"], ensure_ascii=False))


if __name__ == "__main__":
    main()
