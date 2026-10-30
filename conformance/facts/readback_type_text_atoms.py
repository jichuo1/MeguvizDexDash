#!/usr/bin/env python3
"""Read back raw text, A0 displays and original error terminals."""
import hashlib
import json
from pathlib import Path
import sys
import verify_type_text_atoms as audit


def main():
    audit.common.require(len(sys.argv) == 2, "expected one recorded run path")
    base = (audit.ROOT / "artifacts/mdd-026/type-text-audit").resolve()
    folder = (audit.ROOT / sys.argv[1]).resolve()
    audit.common.require(folder.is_relative_to(base) and folder != base, "run path outside type-text audit")
    result_path = folder / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    audit.common.require(not report["task_complete_proven"] and not report["profile_admitted"], "scope overclaimed")
    audit.common.require(report["negative_controls_rejected"] == ["changed_utf16_unit", "changed_raw_mutf8", "non_scalar_as_empty"],
                         "negative controls incomplete")
    audit.common.require(audit.common.digest(audit.common.A0) == report["a0_sha256"] == audit.common.A0_SHA,
                         "A0 identity changed")
    audit.common.require(audit.common.digest(folder / "type_text_probe.exe") == report["native_binary_sha256"],
                         "native binary identity changed")
    for path, sha in report["sources"].items():
        audit.common.require(audit.common.digest(audit.ROOT / path) == sha, "source changed: " + path)
    labels = ["build", "compile"] + ["native-" + name for name in audit.CASES] + [
        "a0-strings-mutf8", "a0-strings-nonscalar", "a0-types-type-names", "a0-types-definitions",
        "native-negative-bad-checksum", "native-negative-unsupported-041"]
    for label in labels:
        path = folder / label
        record = json.loads((path / "record.json").read_text(encoding="utf-8"))
        audit.common.require((record["exit_code"] != 0) == label.startswith("native-negative-"), "terminal differs: " + label)
        for stream in ["stdout", "stderr"]:
            audit.common.require(audit.common.digest(path / (stream + ".txt")) == record[stream + "_sha256"],
                                 "command output changed: " + label + "/" + stream)
    Oracle = audit.oracle_class()
    audit.common.require({item["case"] for item in report["cases"]} == set(audit.CASES), "case set changed")
    total_strings = 0
    for item in report["cases"]:
        name = item["case"]
        path, sha = audit.CASES[name]
        data = (audit.ROOT / path).read_bytes()
        audit.common.require(hashlib.sha256(data).hexdigest() == item["sha256"] == sha, "fixture identity differs")
        oracle = Oracle(data)
        native = json.loads((folder / ("native-" + name) / "stdout.txt").read_text(encoding="utf-8"))
        audit.common.require(native["probe_complete"] and native["operation_status"] == "ok"
                             and native["source"]["content_id"] == "sha256:" + sha, "native terminal differs")
        audit.compare_strings(native["strings"], oracle)
        audit.common.require([x["data"]["descriptor"] for x in native["types"]] == oracle.types, "type descriptors differ")
        total_strings += len(oracle.units)
        if name in ["mutf8", "nonscalar"]:
            raw = (folder / ("a0-strings-" + name) / "stdout.txt").read_bytes()
            rows = audit.common.table(raw, ["idx_hex", "value_hex"])
            actual = [(int(bytes.fromhex(row["idx_hex"]).decode("ascii")), row["value_hex"].lower()) for row in rows]
            audit.common.require(actual == list(enumerate(oracle.raw_strings)), "A0 text bytes differ")
        if name in ["type-names", "definitions"]:
            columns = ["file_id", "type_idx", "descriptor", "java_name"]
            rows = audit.common.table((folder / ("a0-types-" + name) / "stdout.txt").read_bytes(), columns)
            decoded = [{key:None if value == "N" else bytes.fromhex(value).decode("utf-8") for key, value in row.items()} for row in rows]
            expected = [{"file_id":"0", "type_idx":str(index), "descriptor":desc, "java_name":audit.java_name(desc)}
                        for index, desc in enumerate(oracle.types)]
            audit.common.require(decoded == expected, "A0 type name differs")
    for item in report["native_negative_terminals"]:
        path = folder / ("native-negative-" + item["id"])
        actual = json.loads((path / "stdout.txt").read_text(encoding="utf-8"))
        record = json.loads((path / "record.json").read_text(encoding="utf-8"))
        audit.common.require(audit.common.digest(audit.ROOT / item["path"]) == item["sha256"]
                             and record["exit_code"] == item["exit_code"]
                             and actual["operation_status"] == "error" and actual["error"] == item["actual_error"],
                             "negative terminal changed")
    readback = {"status":"passed", "result_sha256":audit.common.digest(result_path),
                "readback_source_sha256":audit.common.digest(Path(__file__)), "cases":len(report["cases"]),
                "string_rows_checked":total_strings, "negative_terminals":len(report["native_negative_terminals"]),
                "source_files_checked":len(report["sources"]), "task_complete_proven":False,
                "scope":"small synthetic DEX; A0 raw MUTF8 display is not standard UTF-8 compatibility"}
    (folder / "readback.json").write_text(json.dumps(readback, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(readback))


if __name__ == "__main__":
    main()
