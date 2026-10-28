#!/usr/bin/env python3
"""Read back captured multi-input oracle and raw process evidence."""
import hashlib
import json
from pathlib import Path
import sys
import zipfile
import verify_cross_dex_identity as audit


def main():
    audit.common.require(len(sys.argv) == 2, "expected one recorded run path")
    base = (audit.ROOT / "artifacts/mdd-026/cross-dex-audit").resolve()
    folder = (audit.ROOT / sys.argv[1]).resolve()
    audit.common.require(folder.is_relative_to(base) and folder != base, "run path outside cross-dex audit")
    result_path = folder / "result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    audit.common.require(not report["task_complete_proven"] and not report["profile_admitted"], "scope overclaimed")
    audit.common.require(report["negative_controls_rejected"] == ["wrong_pool", "missing_row", "wrong_value"],
                         "missing negative controls")
    audit.common.require(audit.common.digest(audit.common.A0) == report["a0_sha256"] == audit.common.A0_SHA,
                         "A0 identity changed")
    audit.common.require(audit.common.digest(folder / "cross_dex_identity_probe.exe") == report["probe_binary_sha256"],
                         "native binary identity changed")
    for path, sha in report["sources"].items():
        audit.common.require(audit.common.digest(audit.ROOT / path) == sha, "source changed: " + path)
    apk = folder / "synthetic-same-content.apk"
    audit.common.require(audit.common.digest(apk) == report["synthetic_apk_sha256"], "APK identity changed")
    content = {}
    for name, (path, sha) in audit.FIXTURES.items():
        content[name] = (audit.ROOT / path).read_bytes()
        audit.common.require(hashlib.sha256(content[name]).hexdigest() == sha, "fixture identity changed")
    with zipfile.ZipFile(apk) as archive:
        audit.common.require(archive.namelist() == ["classes.dex", "classes2.dex"], "synthetic members changed")
        audit.common.require(all(archive.read(name) == content["classic"] for name in archive.namelist()),
                             "synthetic members differ")
    cases = {"duplicate-raw-input":["classic", "classic"], "two-distinct-raw":["classic", "shared"],
             "same-content-multidex-apk":["classic", "classic"]}
    labels = ["build", "compile"]
    for name in cases:
        labels.extend(["native-" + name, "a0-dex-files-" + name, "a0-join-" + name])
    for label in labels:
        path = folder / label
        record = json.loads((path / "record.json").read_text(encoding="utf-8"))
        audit.common.require(record["exit_code"] == 0, "command failed: " + label)
        for stream in ["stdout", "stderr"]:
            audit.common.require(audit.common.digest(path / (stream + ".txt")) == record[stream + "_sha256"],
                                 "command output changed: " + label + "/" + stream)
    audit.common.require({item["case"] for item in report["cases"]} == set(cases), "case list differs")
    Oracle = audit.oracle_class()
    join_columns = ["file_id", "string_pool_id", "string_idx", "value"]
    dex_columns = ["file_id", "string_pool_id", "source_path", "entry_name"]
    join_total = 0
    for item in report["cases"]:
        name = item["case"]
        native = json.loads((folder / ("native-" + name) / "stdout.txt").read_text(encoding="utf-8"))
        occ = native["occurrences"]
        audit.common.require(native["probe_complete"] and native["operation_status"] == "ok" and len(occ) == 2,
                             "native terminal incomplete")
        audit.common.require([x["selected"]["file_id"] for x in occ] == [0, 1], "native IDs differ")
        audit.common.require(len({x["source"]["dex_occurrence_id"] for x in occ}) == 2, "DEX occurrences collapsed")
        rows = audit.decode_rows((folder / ("a0-dex-files-" + name) / "stdout.txt").read_bytes(), dex_columns)
        audit.common.require(rows == item["a0_dex_rows"], "A0 dex-files rows differ")
        joined = audit.decode_rows((folder / ("a0-join-" + name) / "stdout.txt").read_bytes(), join_columns)
        expected = []
        for native_occurrence, row, fixture in zip(occ, rows, cases[name]):
            expected_oracle = Oracle(content[fixture])
            audit.common.require(native_occurrence["source"]["content_id"] == "sha256:" + audit.FIXTURES[fixture][1],
                                 "native content mismatch")
            audit.common.require([x["data"]["text"]["utf16_units"] for x in native_occurrence["strings"]]
                                 == expected_oracle.units, "native UTF16 mismatch")
            audit.common.require([bytes(x["data"]["text"]["raw_mutf8"]).hex() for x in native_occurrence["strings"]]
                                 == expected_oracle.raw_strings, "native raw MUTF8 mismatch")
            audit.common.require([x["data"]["string_idx"] for x in native_occurrence["strings"]]
                                 == list(range(len(expected_oracle.units))), "native coordinates differ")
            expected.extend({"file_id":row["file_id"], "string_pool_id":row["string_pool_id"],
                             "string_idx":str(index), "value":text}
                            for index, text in enumerate(expected_oracle.strings))
        audit.compare_join(joined, expected)
        audit.common.require(len(joined) == item["a0_join_row_count"], "A0 row count differs")
        join_total += len(joined)
    output = {"status":"passed", "result_sha256":audit.common.digest(result_path),
              "readback_source_sha256":audit.common.digest(Path(__file__)), "cases":len(cases),
              "a0_join_rows":join_total, "source_files_checked":len(report["sources"]),
              "task_complete_proven":False,
              "scope":"three synthetic multi-input cases, not production mapping or full HostLab"}
    (folder / "readback.json").write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output))


if __name__ == "__main__":
    main()
