#!/usr/bin/env python3
"""Read back captured code atom outputs against their original source bytes."""
import hashlib
import json
from pathlib import Path
import sys
import verify_code_item_atoms as audit


def main():
    audit.common.require(len(sys.argv) == 2, "expected one recorded run path")
    base = (audit.ROOT / "artifacts/mdd-026/code-item-audit").resolve()
    folder = (audit.ROOT / sys.argv[1]).resolve()
    audit.common.require(folder.is_relative_to(base) and folder != base, "run path outside code-item audit")
    result_path = folder / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    audit.common.require(not report["task_complete_proven"] and not report["profile_admitted"], "scope overclaimed")
    audit.common.require(report["negative_controls_rejected"] == ["missing_owner", "incorrect_null", "incorrect_code_units"],
                         "negative control missing")
    audit.common.require(audit.common.digest(audit.common.A0) == report["a0_sha256"] == audit.common.A0_SHA,
                         "A0 identity changed")
    audit.common.require(audit.common.digest(folder / "code_item_atoms_probe.exe") == report["native_binary_sha256"],
                         "native binary identity changed")
    for path, sha in report["sources"].items():
        audit.common.require(audit.common.digest(audit.ROOT / path) == sha, "source changed: " + path)
    labels = ["build", "compile", "native-classic", "native-shared", "native-physical-try", "a0-classic", "a0-shared"]
    for label in labels:
        path = folder / label
        record = json.loads((path / "record.json").read_text(encoding="utf-8"))
        audit.common.require(record["exit_code"] == 0, "command failed: " + label)
        for stream in ["stdout", "stderr"]:
            audit.common.require(audit.common.digest(path / (stream + ".txt")) == record[stream + "_sha256"],
                                 "command output changed: " + label + "/" + stream)
    Oracle = audit.oracle_class()
    audit.common.require({item["case"] for item in report["results"]} == {"classic", "shared", "physical-try"},
                         "case set changed")
    for result in report["results"]:
        name = result["case"]
        data = (audit.ROOT / result["fixture"]).read_bytes()
        audit.common.require(hashlib.sha256(data).hexdigest() == result["sha256"], "fixture changed")
        output = json.loads((folder / ("native-" + name) / "stdout.txt").read_text(encoding="utf-8"))
        audit.common.require(output["probe_complete"] and output["operation_status"] == "ok"
                             and len(output["dex_occurrences"]) == 1, "native terminal incomplete")
        occurrence = output["dex_occurrences"][0]
        audit.common.require(occurrence["source"]["content_id"] == "sha256:" + result["sha256"]
                             and occurrence["code"]["source"] == occurrence["source"]
                             and occurrence["raw_code_evidence"]["source"] == occurrence["source"], "source binding differs")
        items = {int(item["data"]["raw_range"]["byte_offset"]):item for item in occurrence["code"]["items"]}
        audit.common.require(len(items) == result["physical_items"], "physical item count differs")
        for offset, item in items.items():
            audit.common.require(audit.native_fields(item) == audit.raw_fields(data, offset), "code atoms differ")
        if name == "physical-try":
            offset = audit.map_code_start(data)
            fields = audit.raw_fields(data, offset)
            audit.common.require(set(items) == {offset} and fields["tries_size"] > 0
                                 and fields["tries_off"] is not None and fields["handlers_off"] is not None
                                 and not occurrence["definitions"]["method_definitions"], "physical try differs")
            continue
        reference = Oracle(data)
        expected = [{"file_id":0, "method_idx":method, **audit.raw_fields(data, offset)}
                    for method, owner, flags, offset, class_def in reference.definitions if offset]
        expected.sort(key=lambda row:row["method_idx"])
        native = []
        for method in occurrence["definitions"]["method_definitions"]:
            if method["body"]["state"] == "present":
                offset = int(method["body"]["code_byte_offset"])
                native.append({"file_id":0, "method_idx":method["method_idx"], **audit.native_fields(items[offset])})
        native.sort(key=lambda row:row["method_idx"])
        audit.compare_rows(native, expected)
        a0 = audit.parse_hex_table((folder / ("a0-" + name) / "stdout.txt").read_bytes())
        audit.compare_rows(a0, expected)
        audit.common.require(len(a0) == result["a0_rows"] == result["method_owned_rows"], "row count differs")
        for entry in occurrence["raw_code_evidence"]["methods"]:
            if entry["insns_range"] is None:
                audit.common.require(entry["sha256"] is None, "no body became empty digest")
            else:
                at = int(entry["insns_range"]["byte_offset"])
                length = int(entry["insns_range"]["byte_length"])
                audit.common.require(hashlib.sha256(data[at:at+length]).hexdigest() == entry["sha256"], "raw digest differs")
    readback = {"status":"passed", "result_sha256":audit.common.digest(result_path),
                "readback_source_sha256":audit.common.digest(Path(__file__)), "cases":len(report["results"]),
                "source_files_checked":len(report["sources"]), "task_complete_proven":False,
                "scope":"small synthetic fixtures; non-null try/handler item has no method owner"}
    (folder / "readback.json").write_text(json.dumps(readback, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(readback))


if __name__ == "__main__":
    main()
