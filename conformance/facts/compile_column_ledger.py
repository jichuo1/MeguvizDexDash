#!/usr/bin/env python3
"""Recompute a scoped, non-qualifying field evidence inventory from raw receipts."""
import datetime
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT = ROOT / "artifacts/mdd-026/column-ledger" / STAMP
RUNS = {
    "definition_rows": "artifacts/mdd-026/new-audit/definition-projections",
    "header_bytes": "artifacts/mdd-026/header-audit/20261028T163754102728Z",
    "cross_dex": "artifacts/mdd-026/cross-dex-audit/20261028T164250980578Z",
    "code_atoms": "artifacts/mdd-026/code-item-audit/20261028T164825508666Z",
    "annotations": "artifacts/mdd-026/annotation-order-audit/20261028T165221569757Z",
    "methods": "artifacts/mdd-026/method-atom-audit/20261028T165707192974Z",
    "types_text": "artifacts/mdd-026/type-text-audit/20261028T170219193130Z",
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def identity(relative):
    data = (ROOT / relative).read_bytes()
    return {"path":relative, "bytes":len(data), "sha256":sha(data)}


def verify_readback(result_bytes, readback):
    require(readback.get("status") == "passed" and readback.get("result_sha256") == sha(result_bytes),
            "result/readback identity mismatch")
    require(readback.get("task_complete_proven") is False, "readback overclaims task")


def verify_receipt(record, stdout, stderr, negative):
    require((record.get("exit_code") != 0) == negative, "unexpected command terminal")
    require(record.get("stdout_sha256") == sha(stdout) and record.get("stderr_sha256") == sha(stderr),
            "command stream hash mismatch")


def run_evidence(name, relative):
    folder = ROOT / relative
    result_bytes = (folder / "result.json").read_bytes()
    report = json.loads(result_bytes)
    readback = json.loads((folder / "readback.json").read_bytes())
    verify_readback(result_bytes, readback)
    require(report.get("task_complete_proven") is False and report.get("profile_admitted") is False,
            "slice overclaims qualification: " + name)
    records = []
    for record_path in sorted(folder.glob("*/record.json")):
        record = json.loads(record_path.read_bytes())
        label = record_path.parent.name
        verify_receipt(record, (record_path.parent / "stdout.txt").read_bytes(),
                       (record_path.parent / "stderr.txt").read_bytes(), label.startswith("native-negative-"))
        records.append(identity(record_path.relative_to(ROOT).as_posix()))
    require(len(records) >= 6, "missing per-process records: " + name)
    drift = []
    for path, expected in report["sources"].items():
        absolute = ROOT / path
        actual = sha(absolute.read_bytes()) if absolute.is_file() else None
        if actual != expected:
            drift.append({"path":path, "tested_sha256":expected, "current_sha256":actual})
    return {"result":identity(relative + "/result.json"), "readback":identity(relative + "/readback.json"),
            "verified_process_records":records, "tested_source_count":len(report["sources"]),
            "current_source_drift":drift, "limits":report["limits"]}, report


def main():
    schema_path = "conformance/manifests/relations.json"
    schema = read(schema_path)
    required = [r for r in schema["relations"] if r.get("required_by_hostlab")]
    require(len(required) == schema["required_count"] == 17, "required relation denominator differs")
    require(sum(len(r["columns"]) for r in required) == 156, "required column denominator differs")
    pieces, reports = {}, {}
    for name, folder in RUNS.items():
        pieces[name], reports[name] = run_evidence(name, folder)
    legacy_path = "artifacts/mdd-026/new-audit/column-evidence.json"
    legacy = read(legacy_path)
    legacy_receipt = read("artifacts/mdd-026/new-audit/run-record.json")
    legacy_identity = next(item for item in legacy_receipt["identities"] if item["path"] == legacy_path)
    require(identity(legacy_path)["sha256"] == legacy_identity["sha256"]
            and legacy["task_complete_proven"] is False, "legacy audit identity differs")
    require(all(run["exit_code"] == 0 for run in legacy_receipt["runs"]), "legacy audit process failed")
    require(len(legacy_receipt["runs"]) == 3, "legacy audit command count differs")
    for record, label in zip(legacy_receipt["runs"], ["projection-readback", "audit", "negative-controls"]):
        prefix = ROOT / "artifacts/mdd-026/new-audit" / label
        verify_receipt(record, prefix.with_suffix(".stdout.txt").read_bytes(),
                       prefix.with_suffix(".stderr.txt").read_bytes(), False)
    for entry in legacy["evidence"]:
        require(identity(entry["path"])["sha256"] == entry["sha256"], "legacy input evidence drift: " + entry["path"])
    index_result_path = "artifacts/mdd-026/indexes/runs/20261028T141315875747Z/result.json"
    index_readback_path = "artifacts/mdd-026/indexes/runs/20261028T141315875747Z/readback.json"
    index_result, index_readback = read(index_result_path), read(index_readback_path)
    require(index_result["passed"] and not index_result["profiles_admitted"] and index_readback["passed"]
            and index_readback["result_sha256"] == identity(index_result_path)["sha256"], "index evidence mismatch")
    legacy_relations = {r["name"]:r for r in legacy["relations"]}
    require(set(legacy_relations) == {r["name"] for r in required}, "legacy denominator differs")

    maps = {
        "dex_files": ["header_bytes", "cross_dex"], "strings":["cross_dex", "types_text"],
        "types":["types_text"], "methods":["methods"], "classes":["historical_021"],
        "class_interfaces":["definition_rows"], "class_fields":["definition_rows"],
        "class_methods":["definition_rows"], "code_items":["code_atoms"],
        "annotation_directory_entries":["annotations"], "annotation_set_entries":["annotations"],
        "annotations":["annotations"], "annotation_elements":["annotations"],
        "method_strings":["tiny_differential"], "method_calls":["tiny_differential"],
        "method_field_accesses":["tiny_differential"], "method_used_types":["tiny_differential"],
    }
    require(set(maps) == {r["name"] for r in required}, "unmapped required relation")
    header_columns = set(reports["header_bytes"]["results"][0]["columns_compared"])
    require(len(header_columns) == 24, "header comparison column count differs")
    method_columns = set(reports["methods"]["results"][0]["columns"])
    code_columns = set(next(x for x in reports["code_atoms"]["results"] if x["case"] == "classic")["columns"])
    definition_columns = {r["relation"]:set(r["columns"]) for r in reports["definition_rows"]["results"]}
    annotation_columns = {r["relation"]:set(r["columns"]) for r in reports["annotations"]["a0_multi_input"]}
    require(len(method_columns) == 14 and len(code_columns) == 12, "method/code evidence columns differ")
    entries = []
    for relation in required:
        name = relation["name"]
        historical = {c["name"]:c for c in legacy_relations[name]["columns"]}
        for ordinal, column in enumerate(relation["columns"]):
            key = column["name"]
            old = historical[key]
            require(old["ordinal"] == ordinal and old["data_type"] == column["data_type"]
                    and old["nullable"] == column["nullable"], "frozen schema/matrix mismatch")
            links = []
            if name == "dex_files":
                if key in header_columns:
                    links.append({"slice":"header_bytes", "type":"independent_byte_oracle_native_atoms_and_A0_single_input"})
                elif key in {"file_id", "string_pool_id", "source_path", "entry_name"}:
                    links.append({"slice":"cross_dex", "type":"native_occurrence_and_A0_multi_input_independent_observations"})
            elif name == "strings":
                links.append({"slice":"cross_dex", "type":"ordered_A0_join_and_native_coordinates_independent_oracle"})
                if key == "value":
                    links.append({"slice":"types_text", "type":"utf16_units_and_raw_mutf8_with_strict_scalar_boundary"})
            elif name == "types":
                links.append({"slice":"types_text", "type":"native_type_atoms_and_A0_type_names_conformance_formatter"})
            elif name == "methods" and key in method_columns:
                links.append({"slice":"methods", "type":"ordered_conformance_composition_A0_and_byte_oracle"})
            elif name == "code_items" and key in code_columns:
                links.append({"slice":"code_atoms", "type":"method_owned_conformance_composition_A0_and_byte_oracle"})
            elif name in definition_columns and key in definition_columns[name]:
                links.append({"slice":"definition_rows", "type":"real_row_API_A0_single_input_and_duplicate_source_rebinding"})
            elif name in annotation_columns and key in annotation_columns[name]:
                links.append({"slice":"annotations", "type":"ordered_row_API_byte_oracle_and_A0_double_input_normalized_numeric"})
            if old["historical_a0_metadata_projection_compared"]:
                links.append({"slice":"historical_021", "type":"recorded_A0_metadata_projection_and_reused_typed_fact_identity"})
            if old["full_relation_multiset_compared_on_nonempty_rows"]:
                links.append({"slice":"tiny_differential", "type":"complete_row_multiset_comparison_not_ordering"})
            require(links, "no identified evidence link: " + name + "." + key)
            boundaries = ["Small synthetic fixture observations do not establish all-input or full HostLab coverage."]
            if old["production_projection"] == "unassembled_production_relation":
                boundaries.append("Production frozen compatibility projection remains unassembled; do not infer its behavior.")
            if name in {"dex_files", "strings"} and key in {"file_id", "string_pool_id", "source_path", "entry_name"}:
                boundaries.append("Native physical identity and A0 per-occurrence numeric mapping are distinct; production binding remains unverified.")
            if name == "strings" and key == "value":
                boundaries.append("A0 MUTF8 byte display is not ordinary standard UTF8; non-scalar projection requires explicit policy.")
            if name == "types" and key == "java_name":
                boundaries.append("The formatter used in this evidence is conformance code, not a production row API.")
            if name == "methods":
                boundaries.append("Fourteen values are assembled in conformance code; opcode width oracle is fixture-limited.")
            if name == "code_items" and key in {"tries_off", "handlers_off"}:
                boundaries.append("Non-NULL offsets were observed in an unowned physical code item, not an A0 method-owned row.")
            if name == "annotation_elements" and key == "value_f64":
                boundaries.append("A0 CAST displays two native negative-zero values as positive zero; numeric normalization is not bit equivalence.")
            if name.startswith("method_"):
                boundaries.append("Tiny relation comparison checks a multiset; it does not itself establish required ordering or all source cases.")
            if column["nullable"]:
                boundaries.append("NULL and non-NULL boundary coverage must be assessed against each specific observed case, not inferred from nullable schema.")
            entries.append({"relation":name, "ordinal":ordinal, **column,
                            "production_projection":old["production_projection"], "evidence":links,
                            "sample_null_count_tiny_differential":old["sample_null_count"],
                            "sample_value_count_tiny_differential":old["sample_value_count"],
                            "remaining_boundaries":boundaries, "full_field_qualification":False})
    require(len(entries) == 156, "ledger lost a column")
    report = {"schema_version":"mdd.scoped-field-evidence-ledger.v1", "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "task":"MDD-026", "is_task_gate":False, "task_complete_proven":False, "profile_admitted":False,
              "required_relations":17, "required_columns":156,
              "unassembled_projection_columns":sum(x["production_projection"] == "unassembled_production_relation" for x in entries),
              "columns":entries, "slices":pieces,
              "additional_evidence":[identity(schema_path), identity(legacy_path), identity("artifacts/mdd-026/new-audit/run-record.json"),
                  identity("artifacts/mdd-026/facts-differential.json"), identity("artifacts/mdd-021/reference-comparison.json"),
                  identity("artifacts/mdd-021/reference-evidence-reuse.json"), identity(index_result_path),
                  identity(index_readback_path)],
              "global_remaining":["Original acceptance requires all required fact fields, types, NULL, ordering, multiplicity, source and raw-fingerprint evidence; this table does not sign it.",
                  "Existing scoped tests do not establish complete private-input facts, full HostLab corpus, SQL compatibility, or product profile.",
                  "Declared compatibility relation assembly and provider mapping are separate later work and are not supplied by this evidence inventory.",
                  "Current source drift is listed per slice; old recorded results are not relabeled as current-source test results."]}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "column-ledger.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"path":str(OUT.relative_to(ROOT)), "relations":17, "columns":len(entries),
                      "unassembled_columns":report["unassembled_projection_columns"],
                      "source_drift_slices":[name for name, piece in pieces.items() if piece["current_source_drift"]],
                      "task_complete_proven":False}))


if __name__ == "__main__":
    main()
