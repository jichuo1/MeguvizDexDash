#!/usr/bin/env python3
"""Independently re-read the captured command outputs and row comparisons."""
import json
import verify_definition_projections as probe


def main():
    out = probe.OUT
    result_path = out / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    probe.require(not report["task_complete_proven"] and not report["profile_admitted"], "scope overclaimed")
    probe.require(report["negative_controls_rejected"] == ["wrong_file_id", "unexpected_null", "missing_row"],
                  "negative controls incomplete")
    probe.require(probe.digest(probe.A0) == report["a0_sha256"] == probe.A0_SHA, "A0 identity changed")
    probe.require(probe.digest(probe.ROOT / probe.FIXTURE) == report["fixture_sha256"] == probe.FIXTURE_SHA,
                  "fixture identity changed")
    probe.require(probe.digest(out / "definition_projection_probe.exe") == report["native_binary_sha256"],
                  "probe binary identity changed")
    for path, sha in report["sources"].items():
        probe.require(probe.digest(probe.ROOT / path) == sha, "source identity changed: " + path)
    for label in ["build", "compile", "native", "a0-class_interfaces", "a0-class_fields", "a0-class_methods"]:
        folder = out / label
        record = json.loads((folder / "record.json").read_text(encoding="utf-8"))
        probe.require(record["exit_code"] == 0, "command not successful: " + label)
        for stream in ["stdout", "stderr"]:
            probe.require(probe.digest(folder / (stream + ".txt")) == record[stream + "_sha256"],
                          "command output changed: " + label + "/" + stream)
    native = json.loads((out / "native/stdout.txt").read_text(encoding="utf-8"))
    occurrences = native["selected_occurrences"]
    probe.require(native["probe_complete"] and len(occurrences) == 2, "native result incomplete")
    probe.require([item["selected"]["file_id"] for item in occurrences] == [0, 1], "file IDs differ")
    probe.require(len({item["selected"]["source_occurrence_id"] for item in occurrences}) == 2,
                  "source occurrences collapsed")
    for relation in report["results"]:
        name, columns = relation["relation"], relation["columns"]
        actual = probe.table((out / ("a0-" + name) / "stdout.txt").read_bytes(), columns)
        probe.require(len(actual) == relation["a0_rows"] and bool(actual), "A0 row count differs")
        for item in occurrences:
            probe.compare_rows(actual, item[name], columns, item["selected"]["file_id"])
    readback = {"status": "passed", "result_sha256": probe.digest(result_path),
                "relations": len(report["results"]), "source_files_checked": len(report["sources"]),
                "task_complete_proven": False,
                "scope": "captured synthetic fixture and single-input A0 rows; not A0 multi-input equality"}
    (out / "readback.json").write_text(json.dumps(readback, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(readback))


if __name__ == "__main__":
    main()
