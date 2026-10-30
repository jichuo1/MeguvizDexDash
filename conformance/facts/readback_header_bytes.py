#!/usr/bin/env python3
"""Recheck recorded header inputs, raw process outputs, and comparisons."""
import hashlib
import json
from pathlib import Path
import sys
import verify_header_bytes as audit


def main():
    audit.common.require(len(sys.argv) == 2, "expected one recorded run path")
    base = (audit.ROOT / "artifacts/mdd-026/header-audit").resolve()
    folder = (audit.ROOT / sys.argv[1]).resolve()
    audit.common.require(folder.is_relative_to(base) and folder != base, "run path outside header audit")
    result_path = folder / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    audit.common.require(not report["task_complete_proven"] and not report["profile_admitted"], "scope overclaimed")
    audit.common.require(report["negative_controls_rejected"] == ["checksum_corruption", "payload_corruption",
                         "signature_corruption_with_valid_checksum", "native_field_corruption"], "missing negative control")
    audit.common.require(audit.common.digest(audit.common.A0) == report["a0_sha256"] == audit.common.A0_SHA,
                         "fixed A0 identity changed")
    audit.common.require(audit.common.digest(folder / "header_byte_probe.exe") == report["native_binary_sha256"],
                         "native binary identity changed")
    for path, sha in report["sources"].items():
        audit.common.require(audit.common.digest(audit.ROOT / path) == sha, "source changed: " + path)
    labels = ["build", "compile"]
    for name in audit.CASES:
        labels.extend(["native-" + name, "a0-" + name])
    for label in labels:
        command = folder / label
        record = json.loads((command / "record.json").read_text(encoding="utf-8"))
        audit.common.require(record["exit_code"] == 0, "command failed: " + label)
        for stream in ["stdout", "stderr"]:
            audit.common.require(audit.common.digest(command / (stream + ".txt")) == record[stream + "_sha256"],
                                 "output changed: " + label + "/" + stream)
    audit.common.require({r["case"] for r in report["results"]} == set(audit.CASES), "case list changed")
    for item in report["results"]:
        name = item["case"]
        path, sha = audit.CASES[name]
        raw = (audit.ROOT / path).read_bytes()
        audit.common.require(hashlib.sha256(raw).hexdigest() == sha == item["sha256"], "fixture changed")
        expected = audit.oracle(raw)
        native = json.loads((folder / ("native-" + name) / "stdout.txt").read_text(encoding="utf-8"))
        occurrences = native["occurrences"]
        audit.common.require(native["probe_complete"] and native["operation_status"] == "ok"
                             and len(occurrences) == 2, "native terminal incomplete")
        audit.common.require([x["selected"]["file_id"] for x in occurrences] == [0, 1], "file IDs changed")
        audit.common.require(len({x["source"]["source_occurrence_id"] for x in occurrences}) == 2,
                             "source occurrences collapsed")
        audit.common.require(len({x["source"]["dex_occurrence_id"] for x in occurrences}) == 2,
                             "DEX occurrences collapsed")
        for occurrence in occurrences:
            audit.common.require(occurrence["source"]["content_id"] == "sha256:" + sha, "source hash mismatch")
            audit.compare_native(occurrence, expected)
        rows = audit.common.table((folder / ("a0-" + name) / "stdout.txt").read_bytes(), audit.COLUMNS)
        audit.common.require(rows == [{col:audit.common.encode(expected[col]) for col in audit.COLUMNS}],
                             "A0 header rows differ")
    output = {"status":"passed", "result_sha256":audit.common.digest(result_path),
              "readback_source_sha256":audit.common.digest(Path(__file__)),
              "cases":len(report["results"]), "fields_per_case":len(audit.COLUMNS),
              "source_files_checked":len(report["sources"]), "task_complete_proven":False,
              "scope":"3 small fixtures and A0 single-input queries; not full HostLab or A0 multi-input"}
    (folder / "readback.json").write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output))


if __name__ == "__main__":
    main()
