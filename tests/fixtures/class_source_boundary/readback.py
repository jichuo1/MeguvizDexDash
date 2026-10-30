#!/usr/bin/env python3
"""Append-only readback of class source boundary and real error evidence."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import verify as audit


def main():
    audit.common.require(len(sys.argv) == 2,"expected one recorded run path")
    base = (audit.ROOT/"artifacts/mdd-026/class-source-audit").resolve()
    folder = (audit.ROOT/sys.argv[1]).resolve()
    audit.common.require(folder.is_relative_to(base) and folder != base,"run outside class source evidence")
    result_path = folder/"result.json"
    report = json.loads(result_path.read_text(encoding="utf-8"))
    audit.common.require(not report["task_complete_proven"] and not report["profile_admitted"],"scope overclaimed")
    audit.common.require(report["negative_controls_rejected"] == ["null_to_empty","empty_to_null","surrogate_to_replacement",
                         "collapsed_duplicate_descriptor","swapped_sources"],"negative controls incomplete")
    audit.common.require(audit.common.digest(audit.common.A0) == report["a0_sha256"] == audit.common.A0_SHA
                         and audit.common.digest(audit.SDK) == report["sdk_dexdump_sha256"] == audit.SDK_SHA,
                         "external binary identity changed")
    audit.common.require(audit.common.digest(folder/"class_source_probe.exe") == report["native_binary_sha256"],
                         "native binary identity changed")
    for path,sha in report["sources"].items():
        audit.common.require(audit.common.digest(audit.ROOT/path) == sha,"source changed: " + path)
    labels = ["build","compile","native-multi","a0-multi"]+["sdk-"+case for case in audit.CASES]+["native-bad","sdk-bad","a0-bad"]
    exits = {}
    for label in labels:
        path = folder/label
        record = json.loads((path/"record.json").read_text(encoding="utf-8"))
        exits[label] = record["exit_code"]
        for stream in ["stdout","stderr"]:
            audit.common.require(audit.common.digest(path/(stream+".txt")) == record[stream+"_sha256"],
                                 "process output changed: " + label + "/" + stream)
        if label not in ["native-bad","sdk-bad","a0-bad"]:
            audit.common.require(record["exit_code"] == 0,"valid command failed: " + label)
    gen_path = audit.ROOT/"tests/fixtures/class_source_boundary/generate.py"
    spec = importlib.util.spec_from_file_location("mdd_class_source_generator",gen_path)
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    manifest = json.loads((audit.ROOT/"tests/fixtures/class_source_boundary/manifest.json").read_text(encoding="utf-8"))
    fixtures = {item["id"]:item for item in manifest["files"]}
    audit.common.require(set(fixtures) == set(audit.CASES+["bad-source-index"]),"fixture set changed")
    expected = []
    for index, item in enumerate(report["fixtures"]):
        case = item["id"]
        raw = (audit.ROOT/"tests/fixtures/class_source_boundary"/fixtures[case]["path"]).read_bytes()
        rebuilt,layout = gen.build(case)
        audit.common.require(raw == rebuilt and layout == fixtures[case]["hand_layout"]
                             and hashlib.sha256(raw).hexdigest() == item["sha256"] == fixtures[case]["sha256"],
                             "fixture reproduction differs")
        actual = audit.oracle(raw,index)
        audit.common.require(actual == item["oracle"],"independent oracle differs")
        expected.append(actual)
    native = json.loads((folder/"native-multi/stdout.txt").read_text(encoding="utf-8"))
    occ = native["occurrences"]
    audit.common.require(native["probe_complete"] and native["operation_status"] == "ok" and len(occ) == 4
                         and [item["selected"]["file_id"] for item in occ] == list(range(4))
                         and len({item["source"]["dex_occurrence_id"] for item in occ}) == 4,"source occurrences differ")
    for item,ref,fixture in zip(occ,expected,report["fixtures"]):
        audit.common.require(item["source"]["content_id"] == "sha256:" + fixture["sha256"]
                             and len(item["classes"]) == 1,"source identity differs")
        cls = item["classes"][0]
        fact = cls["fact"]
        audit.common.require(fact["class_idx"] == ref["class_idx"] and fact["class_def_idx"] == ref["class_def_idx"]
                             and fact["descriptor"] == ref["descriptor"] and fact["access_flags"] == ref["access_flags"]
                             and fact["superclass_descriptor"] == ref["superclass_descriptor"]
                             and cls["source_file_strict"] == ref["source_file_strict"],"class facts differ")
        if ref["source_file_raw_hex"] is None:
            audit.common.require(fact["source_file"] is None and fact["source_file_idx"] is None,"source NULL changed")
        else:
            audit.common.require(bytes(fact["source_file"]["raw_mutf8"]).hex() == ref["source_file_raw_hex"]
                                 and fact["source_file"]["utf16_units"] == ref["source_file_utf16"],"source text changed")
    a0 = audit.common.table((folder/"a0-multi/stdout.txt").read_bytes(),audit.COLUMNS)
    audit.compare(a0,[audit.a0_row(item) for item in expected])
    audit.common.require(len(a0) == report["a0_ordered_rows"] == 4,"A0 row count differs")
    bad = fixtures["bad-source-index"]
    bad_raw = (audit.ROOT/"tests/fixtures/class_source_boundary"/bad["path"]).read_bytes()
    rebuilt,_ = gen.build("bad-source-index")
    audit.common.require(bad_raw == rebuilt and hashlib.sha256(bad_raw).hexdigest() == bad["sha256"],"bad fixture differs")
    try:
        audit.oracle(bad_raw,0)
    except RuntimeError as error:
        audit.common.require(str(error) == "source index outside string pool","bad byte error differs")
    else:
        raise RuntimeError("bad source index passed byte oracle")
    native_bad = json.loads((folder/"native-bad/stdout.txt").read_text(encoding="utf-8"))
    boundary = report["bad_source_index"]
    audit.common.require(exits["native-bad"] == boundary["native_exit"] != 0
                         and native_bad["error"] == boundary["native_error"] and native_bad["error"]["code"] == "INVALID_INPUT"
                         and native_bad["error"]["details"]["reason"] == "INDEX_OUT_OF_RANGE","native error changed")
    audit.common.require(exits["sdk-bad"] == boundary["sdk_exit_observed"] != 0
                         and b"Bad index for class_def.source_file" in (folder/"sdk-bad/stderr.txt").read_bytes(),"SDK error changed")
    a0_bad = audit.common.table((folder/"a0-bad/stdout.txt").read_bytes(),audit.COLUMNS)
    audit.common.require(exits["a0-bad"] == boundary["a0_exit_observed"] == 0
                         and len(a0_bad) == 1 and a0_bad[0]["source_file"] == "N","A0 bad-source observation changed")
    started = datetime.datetime.now(datetime.timezone.utc)
    target = folder/"readbacks"/started.strftime("%Y%m%dT%H%M%S%fZ")
    target.mkdir(parents=True,exist_ok=False)
    result = {"status":"passed","result_sha256":audit.common.digest(result_path),
              "readback_source_sha256":audit.common.digest(Path(__file__)),"command_records_checked":len(labels),
              "source_files_checked":len(report["sources"]),"source_occurrences":len(occ),"negative_controls":5,
              "a0_invalid_source_exit":exits["a0-bad"],"task_complete_proven":False,
              "scope":"small synthetic class facts; A0 source display is raw MUTF8 and invalid index was not rejected"}
    payload = (json.dumps(result)+"\n").encode("utf-8")
    (target/"result.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    (target/"stdout.txt").write_bytes(payload)
    (target/"stderr.txt").write_bytes(b"")
    (target/"command.json").write_text(json.dumps({"argv":[sys.executable,"-O","tests/fixtures/class_source_boundary/readback.py",sys.argv[1]],
        "started_utc":started.isoformat(),"finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"exit_code":0,
        "stdout_sha256":hashlib.sha256(payload).hexdigest(),"stderr_sha256":hashlib.sha256(b"").hexdigest()},indent=2)+"\n",encoding="utf-8")
    sys.stdout.buffer.write(payload)


if __name__ == "__main__":
    main()
