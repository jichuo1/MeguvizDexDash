#!/usr/bin/env python3
"""Add source/null/non-scalar class evidence to a recomputed v2 inventory."""
import datetime
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import compile_column_ledger as base

ROOT = base.ROOT
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT = ROOT / "artifacts/mdd-026/column-ledger-v3" / STAMP
SOURCE = "artifacts/mdd-026/class-source-audit/20261028T174234924728Z"
READBACK = SOURCE + "/readbacks/20261028T174328230167Z"
GENERATION = "artifacts/mdd-026/class-source-audit/20261028T174100079609Z/generate"


def load(relative):
    return json.loads((ROOT/relative).read_text(encoding="utf-8"))


def verify_command(folder, expected_exit):
    record = load(folder+"/record.json")
    base.require(record["exit_code"] == expected_exit,"class source command terminal mismatch: "+folder)
    base.verify_receipt(record,(ROOT/folder/"stdout.txt").read_bytes(),
                        (ROOT/folder/"stderr.txt").read_bytes(),expected_exit != 0)
    return base.identity(folder+"/record.json")


def verify_bad_terminal(report, native, sdk_stderr, a0_rows):
    bad = report["bad_source_index"]
    base.require(bad["native_exit"] != 0 and bad["sdk_exit_observed"] != 0 and bad["a0_exit_observed"] == 0,
                 "bad source index terminal differs")
    base.require(native["operation_status"] == "error" and native["error"] == bad["native_error"]
                 and native["error"]["code"] == "INVALID_INPUT"
                 and native["error"]["details"]["reason"] == "INDEX_OUT_OF_RANGE",
                 "bad source input error was changed or wrapped")
    base.require(b"Bad index for class_def.source_file" in sdk_stderr and len(a0_rows) == 1
                 and a0_rows[0]["source_file"] == "N","SDK/A0 bad source observations differ")


def inspect_class_source():
    report = load(SOURCE+"/result.json")
    base.require(not report["task_complete_proven"] and not report["profile_admitted"],"class source scope overclaimed")
    readback = load(READBACK+"/result.json")
    readback_command = load(READBACK+"/command.json")
    base.require(readback["status"] == "passed" and not readback["task_complete_proven"]
                 and readback["result_sha256"] == base.identity(SOURCE+"/result.json")["sha256"]
                 and readback["source_occurrences"] == 4 and readback["command_records_checked"] == 11,
                 "class source readback mismatch")
    base.verify_receipt(readback_command,(ROOT/READBACK/"stdout.txt").read_bytes(),
                        (ROOT/READBACK/"stderr.txt").read_bytes(),False)
    base.require(report["negative_controls_rejected"] == ["null_to_empty","empty_to_null","surrogate_to_replacement",
                 "collapsed_duplicate_descriptor","swapped_sources"],"class source negative controls incomplete")
    records = [verify_command(GENERATION,0)]
    labels = ["build","compile","native-multi","a0-multi"]+["sdk-"+name for name in
              ["null-source","empty-source","surrogate-source","root-empty-source"]]
    for label in labels:
        records.append(verify_command(SOURCE+"/"+label,0))
    bad = report["bad_source_index"]
    for label,code in [("native-bad",bad["native_exit"]),("sdk-bad",bad["sdk_exit_observed"]),
                       ("a0-bad",bad["a0_exit_observed"])]:
        records.append(verify_command(SOURCE+"/"+label,code))
    verifier_path = ROOT/"tests/fixtures/class_source_boundary/verify.py"
    generator_path = ROOT/"tests/fixtures/class_source_boundary/generate.py"
    base.require(base.sha(verifier_path.read_bytes()) == report["sources"]["tests/fixtures/class_source_boundary/verify.py"]
                 and base.sha(generator_path.read_bytes()) == report["sources"]["tests/fixtures/class_source_boundary/generate.py"],
                 "class source byte oracle or generator changed")
    spec = importlib.util.spec_from_file_location("mdd_class_source_v3_oracle",verifier_path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    spec = importlib.util.spec_from_file_location("mdd_class_source_v3_generator",generator_path)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    base.require(verifier.common.digest(verifier.common.A0) == report["a0_sha256"] == verifier.common.A0_SHA
                 and verifier.common.digest(verifier.SDK) == report["sdk_dexdump_sha256"] == verifier.SDK_SHA,
                 "class source external binary identity differs")
    manifest_path = "tests/fixtures/class_source_boundary/manifest.json"
    fixtures = {item["id"]:item for item in load(manifest_path)["files"]}
    base.require(set(fixtures) == set(verifier.CASES+["bad-source-index"]),"class source fixture denominator differs")
    expected = []
    for index,item in enumerate(report["fixtures"]):
        case = item["id"]
        raw = (ROOT/"tests/fixtures/class_source_boundary"/fixtures[case]["path"]).read_bytes()
        rebuilt,layout = generator.build(case)
        base.require(raw == rebuilt and base.sha(raw) == item["sha256"] == fixtures[case]["sha256"]
                     and layout == fixtures[case]["hand_layout"],"class fixture reproduction differs")
        reference = verifier.oracle(raw,index)
        base.require(reference == item["oracle"],"class byte oracle differs")
        expected.append(reference)
    base.require([x["source_file_strict"]["status"] for x in expected] == ["absent","scalar","non_scalar","scalar"]
                 and expected[1]["source_file_strict"]["value"] == "" and expected[3]["superclass_descriptor"] is None,
                 "class source boundary observations missing")
    native = load(SOURCE+"/native-multi/stdout.txt")
    occurrences = native["occurrences"]
    base.require(native["probe_complete"] and native["operation_status"] == "ok" and len(occurrences) == 4
                 and [x["selected"]["file_id"] for x in occurrences] == list(range(4))
                 and len({x["source"]["dex_occurrence_id"] for x in occurrences}) == 4,"native source multiplicity differs")
    for item,ref,fixture in zip(occurrences,expected,report["fixtures"]):
        base.require(item["source"]["content_id"] == "sha256:"+fixture["sha256"] and len(item["classes"]) == 1,
                     "class source content differs")
        cls = item["classes"][0]
        fact = cls["fact"]
        base.require(fact["class_def_idx"] == ref["class_def_idx"] and fact["class_idx"] == ref["class_idx"]
                     and fact["descriptor"] == ref["descriptor"] and fact["superclass_descriptor"] == ref["superclass_descriptor"]
                     and cls["source_file_strict"] == ref["source_file_strict"],"class native source facts differ")
        if ref["source_file_raw_hex"] is None:
            base.require(fact["source_file"] is None and fact["source_file_idx"] is None,"class source NULL differs")
        else:
            base.require(bytes(fact["source_file"]["raw_mutf8"]).hex() == ref["source_file_raw_hex"]
                         and fact["source_file"]["utf16_units"] == ref["source_file_utf16"],"class source raw text differs")
    rows = verifier.common.table((ROOT/SOURCE/"a0-multi/stdout.txt").read_bytes(),verifier.COLUMNS)
    verifier.compare(rows,[verifier.a0_row(item) for item in expected])
    bad_rows = verifier.common.table((ROOT/SOURCE/"a0-bad/stdout.txt").read_bytes(),verifier.COLUMNS)
    verify_bad_terminal(report,load(SOURCE+"/native-bad/stdout.txt"),(ROOT/SOURCE/"sdk-bad/stderr.txt").read_bytes(),bad_rows)
    drift = []
    for path, expected_sha in report["sources"].items():
        full = ROOT/path
        actual = base.sha(full.read_bytes()) if full.is_file() else None
        if actual != expected_sha:
            drift.append({"path":path,"tested_sha256":expected_sha,"current_sha256":actual})
    return {"result":base.identity(SOURCE+"/result.json"),"readback":base.identity(READBACK+"/result.json"),
            "readback_command":base.identity(READBACK+"/command.json"),"verified_process_records":records,
            "fixture_manifest":base.identity(manifest_path),"current_source_drift":drift,
            "native_invalid_source_code":bad["native_error"]["code"],"a0_invalid_source_exit":bad["a0_exit_observed"],
            "scope":"four synthetic source occurrences; strict non-scalar rejection; A0 raw MUTF8 hex",
            "limits":report["limits"]}


def main():
    OUT.mkdir(parents=True,exist_ok=False)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    proc = subprocess.run([sys.executable,"-O","conformance/facts/compile_column_ledger_v2.py"],
                          cwd=ROOT,capture_output=True,timeout=90)
    (OUT/"base-compiler.stdout.txt").write_bytes(proc.stdout)
    (OUT/"base-compiler.stderr.txt").write_bytes(proc.stderr)
    (OUT/"base-compiler.record.json").write_text(json.dumps({"argv":[sys.executable,"-O","conformance/facts/compile_column_ledger_v2.py"],
        "started_utc":started,"finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"exit_code":proc.returncode,
        "stdout_sha256":base.sha(proc.stdout),"stderr_sha256":base.sha(proc.stderr)},indent=2)+"\n",encoding="utf-8")
    base.require(proc.returncode == 0,"v2 ledger recomputation failed; output retained")
    summary = json.loads(proc.stdout)
    base_path = Path(summary["path"])/"column-ledger.json"
    report = load(base_path.as_posix())
    base.require(report["required_relations"] == 17 and report["required_columns"] == 156
                 and not report["task_complete_proven"] and not report["profile_admitted"],"base scope differs")
    evidence = inspect_class_source()
    report["schema_version"] = "mdd.scoped-field-evidence-ledger.v3"
    report["created_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report["base_recomputation"] = base.identity(base_path.as_posix())
    report["slices"]["class_source_boundaries"] = evidence
    updated = []
    for column in report["columns"]:
        if column["relation"] != "classes":
            continue
        column["evidence"].append({"slice":"class_source_boundaries",
                                  "type":"four_source_ordered_native_byte_oracle_and_A0_raw_text"})
        if column["name"] == "source_file":
            column["remaining_boundaries"].append("NULL, empty and non-scalar source names observed in tiny fixtures; broader names and production projection remain unqualified.")
        if column["name"] == "superclass_descriptor":
            column["remaining_boundaries"].append("Root NULL and non-NULL superclass observed in tiny fixtures; broader input coverage remains unqualified.")
        base.require(column["full_field_qualification"] is False,"field qualification overclaimed")
        updated.append(column["name"])
    base.require(len(updated) == 8 and report["unassembled_projection_columns"] == 69,"class column denominator changed")
    base.require(all(x["full_field_qualification"] is False for x in report["columns"]),"field was promoted")
    report["global_remaining"].append("Out-of-range source_file index is INVALID_INPUT in native and rejected by SDK; A0 returns NULL, which does not excuse the real error.")
    report["is_task_gate"] = False
    report["task_complete_proven"] = False
    report["profile_admitted"] = False
    (OUT/"column-ledger.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps({"path":str(OUT.relative_to(ROOT)),"relations":17,"columns":156,
                      "class_source_columns_updated":len(updated),"unassembled_columns":69,
                      "source_drift_count":len(evidence["current_source_drift"]),"task_complete_proven":False}))


if __name__ == "__main__":
    main()
