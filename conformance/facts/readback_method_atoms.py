#!/usr/bin/env python3
"""Read recorded method rows again against independently decoded fixture bytes."""
import hashlib
import json
from pathlib import Path
import sys
import verify_method_atoms as audit


def main():
    audit.common.require(len(sys.argv) == 2, "expected one recorded run path")
    base = (audit.ROOT / "artifacts/mdd-026/method-atom-audit").resolve()
    folder = (audit.ROOT / sys.argv[1]).resolve()
    audit.common.require(folder.is_relative_to(base) and folder != base, "run path outside method audit")
    result_path = folder / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    audit.common.require(not report["task_complete_proven"] and not report["profile_admitted"], "scope overclaimed")
    audit.common.require(report["negative_controls_rejected"] == ["missing_shared_owner", "no_body_becomes_null",
        "reference_becomes_empty", "code_units_as_instruction_count", "reversed_parameters"], "negative controls incomplete")
    audit.common.require(audit.common.digest(audit.common.A0) == report["a0_sha256"] == audit.common.A0_SHA,
                         "fixed A0 identity changed")
    audit.common.require(audit.common.digest(folder / "method_atoms_probe.exe") == report["native_binary_sha256"],
                         "native binary identity changed")
    for path, sha in report["sources"].items():
        audit.common.require(audit.common.digest(audit.ROOT / path) == sha, "source changed: " + path)
    labels = ["build", "compile"] + [label + name for name in audit.CASES for label in ["native-", "a0-"]]
    for label in labels:
        path = folder / label
        record = json.loads((path / "record.json").read_text(encoding="utf-8"))
        audit.common.require(record["exit_code"] == 0, "command failed: " + label)
        for stream in ["stdout", "stderr"]:
            audit.common.require(audit.common.digest(path / (stream + ".txt")) == record[stream + "_sha256"],
                                 "command output changed: " + label + "/" + stream)
    Oracle = audit.oracle_class()
    audit.common.require({item["case"] for item in report["results"]} == set(audit.CASES), "case set changed")
    total = 0
    for item in report["results"]:
        name = item["case"]
        path, sha = audit.CASES[name]
        data = (audit.ROOT / path).read_bytes()
        audit.common.require(hashlib.sha256(data).hexdigest() == item["sha256"] == sha, "fixture identity differs")
        expected = audit.reference_rows(Oracle(data))
        output = json.loads((folder / ("native-" + name) / "stdout.txt").read_text(encoding="utf-8"))
        audit.common.require(output["probe_complete"] and output["operation_status"] == "ok"
                             and len(output["dex_occurrences"]) == 1, "native terminal incomplete")
        occurrence = output["dex_occurrences"][0]
        audit.common.require(occurrence["source"]["content_id"] == "sha256:" + sha
                             and occurrence["code"]["source"] == occurrence["source"], "source binding differs")
        audit.compare_rows(audit.native_rows(occurrence), expected)
        audit.compare_rows(audit.decode_a0((folder / ("a0-" + name) / "stdout.txt").read_bytes()), expected)
        audit.common.require(len(expected) == item["rows"], "method row count differs")
        total += len(expected)
    readback = {"status":"passed", "result_sha256":audit.common.digest(result_path),
                "readback_source_sha256":audit.common.digest(Path(__file__)), "cases":len(report["results"]),
                "rows":total, "source_files_checked":len(report["sources"]), "task_complete_proven":False,
                "scope":"three small fixtures; method rows assembled by conformance driver, not production"}
    (folder / "readback.json").write_text(json.dumps(readback, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(readback))


if __name__ == "__main__":
    main()
