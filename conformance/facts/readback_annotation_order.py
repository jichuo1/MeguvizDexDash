#!/usr/bin/env python3
"""Read back source-bound ordered annotation and A0 observations."""
import hashlib
import json
from pathlib import Path
import sys
import verify_annotation_order as audit


def main():
    audit.common.require(len(sys.argv) == 2, "expected one recorded run path")
    base = (audit.ROOT / "artifacts/mdd-026/annotation-order-audit").resolve()
    folder = (audit.ROOT / sys.argv[1]).resolve()
    audit.common.require(folder.is_relative_to(base) and folder != base, "run path outside annotation audit")
    result_path = folder / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    audit.common.require(not report["task_complete_proven"] and not report["profile_admitted"], "scope overclaimed")
    audit.common.require(report["negative_controls_rejected"] == ["swapped_order", "null_to_zero", "dropped_row"],
                         "negative controls incomplete")
    audit.common.require(audit.common.digest(audit.common.A0) == report["a0_sha256"] == audit.common.A0_SHA,
                         "fixed A0 identity changed")
    audit.common.require(audit.common.digest(folder / "annotation_order_probe.exe") == report["native_binary_sha256"],
                         "native binary identity changed")
    for path, sha in report["sources"].items():
        audit.common.require(audit.common.digest(audit.ROOT / path) == sha, "source changed: " + path)
    labels = ["build", "compile", "native-complete", "native-parameter-positions-unknown"] + [
        "a0-" + relation for relation in audit.RELATIONS]
    for label in labels:
        path = folder / label
        record = json.loads((path / "record.json").read_text(encoding="utf-8"))
        audit.common.require(record["exit_code"] == 0, "command failed: " + label)
        for stream in ["stdout", "stderr"]:
            audit.common.require(audit.common.digest(path / (stream + ".txt")) == record[stream + "_sha256"],
                                 "command output changed: " + label + "/" + stream)
    schema = json.loads((audit.ROOT / "conformance/manifests/relations.json").read_text(encoding="utf-8"))
    relations = {item["name"]:item["columns"] for item in schema["relations"] if item["name"] in audit.RELATIONS}
    Oracle = audit.oracle_class()
    audit.common.require({item["case"] for item in report["cases"]} == {"complete", "parameter-positions-unknown"},
                         "case set changed")
    good = None
    for item in report["cases"]:
        case = item["case"]
        data = (audit.ROOT / item["fixture"]).read_bytes()
        audit.common.require(hashlib.sha256(data).hexdigest() == item["sha256"], "fixture identity differs")
        expected = Oracle(data).read()
        output = json.loads((folder / ("native-" + case) / "stdout.txt").read_text(encoding="utf-8"))
        occ = output["occurrences"]
        audit.common.require(output["probe_complete"] and output["operation_status"] == "ok" and len(occ) == 2,
                             "native terminal incomplete")
        audit.common.require([x["selected"]["file_id"] for x in occ] == [0, 1]
                             and len({x["source"]["dex_occurrence_id"] for x in occ}) == 2, "source identity differs")
        for x in occ:
            audit.common.require(x["source"]["content_id"] == "sha256:" + item["sha256"], "source hash mismatch")
            error = x["prototype_positions_error"]
            if case == "parameter-positions-unknown":
                audit.common.require(error is not None and error["code"] == "INCOMPLETE_FACTS"
                    and error["details"]["required_layer"] == "prototype_parameter_annotation_positions"
                    and error["details"]["dex_occurrence_id"] == x["source"]["dex_occurrence_id"], "unknown position lost")
            else:
                audit.common.require(error is None, "complete fixture failed position gate")
            for relation in audit.RELATIONS:
                rows = x["rows"][relation]
                audit.compare_exact(rows, [dict(row, file_id=x["selected"]["file_id"]) for row in expected[relation]])
                audit.validate_types(rows, relations[relation])
        if case == "complete":
            good = occ
    audit.common.require(good is not None, "missing complete case")
    negative_zero_changes = 0
    total = 0
    for observed in report["a0_multi_input"]:
        name = observed["relation"]
        columns = relations[name]
        names = [c["name"] for c in columns]
        raw = (folder / ("a0-" + name) / "stdout.txt").read_bytes()
        rows = audit.common.table(raw, names)
        actual = [{key:None if value == "N" else bytes.fromhex(value).decode("utf-8", "strict")
                   for key, value in row.items()} for row in rows]
        expected = [row for occurrence in good for row in occurrence["rows"][name]]
        expected.sort(key=lambda row:tuple(row[key] for key in audit.SORT_KEYS[name]))
        changes = audit.a0_equal(actual, expected, columns)
        audit.common.require(changes == observed["negative_zero_display_sign_changes"] and len(actual) == observed["rows"],
                             "A0 observation changed")
        negative_zero_changes += changes
        total += len(actual)
    audit.common.require(negative_zero_changes == report["a0_negative_zero_display_sign_changes"],
                         "A0 zero-sign observation changed")
    readback = {"status":"passed", "result_sha256":audit.common.digest(result_path),
                "readback_source_sha256":audit.common.digest(Path(__file__)), "relations":len(audit.RELATIONS),
                "a0_rows":total, "a0_negative_zero_display_sign_changes":negative_zero_changes,
                "source_files_checked":len(report["sources"]), "task_complete_proven":False,
                "scope":"two tiny duplicated fixtures; A0 numeric comparison normalizes zero sign"}
    (folder / "readback.json").write_text(json.dumps(readback, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(readback))


if __name__ == "__main__":
    main()
