#!/usr/bin/env python3
"""Read back the bounded independent row probe without signing a product profile."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(path):
    data = path.read_bytes()
    return {"bytes":len(data), "sha256":hashlib.sha256(data).hexdigest()}


def read(path):
    return json.loads(path.read_text(encoding="utf8"))


def main():
    build_path, probe_path = HERE / "build-4/record.json", HERE / "probe-5/record.json"
    build, probe = read(build_path), read(probe_path)
    for label, record in (("build",build), ("probe",probe)):
        require(record["exit_code"] == 0 and record["job_status"] == "completed"
                and record["tree_empty_verified"] is True and record["sources_unchanged"] is True
                and record["orchestration_unchanged"] is True, label + " incomplete")
        folder = HERE / ("build-4" if label == "build" else "probe-5")
        for stream in ("stdout", "stderr"):
            require(identity(folder / (stream+".txt"))["sha256"] == record[stream+"_sha256"], label + " output changed")
        require(identity(folder / "supervisor.json")["sha256"] == record["supervisor_sha256"], label + " supervisor changed")
    require(probe["bound_build_record"] == build_path.relative_to(ROOT).as_posix()
            and probe["bound_build_record_sha256"] == identity(build_path)["sha256"]
            and probe["binary_sha256"] == build["binary_sha256"]
            and probe["sources_before"] == build["sources_after"], "build/probe identity mismatch")
    for path, expected in probe["sources_after"].items():
        require(identity(ROOT/path)["sha256"] == expected, "current source drift: " + path)
    for path, expected in probe["orchestration_after"].items():
        require(identity(ROOT/path)["sha256"] == expected, "runner source drift: " + path)
    binary = ROOT / "artifacts/local/row-capacity-independent-20261029-target/debug/mdd-row-capacity-independent.exe"
    require(identity(binary)["sha256"] == build["binary_sha256"], "current binary drift")
    def external(path):
        entries = tomllib.loads(path.read_text(encoding="utf8"))["package"]
        return {(x["name"],x["version"],x.get("checksum")) for x in entries if x.get("source")}
    root_lock, probe_lock = external(ROOT/"Cargo.lock"), external(HERE/"Cargo.lock")
    require(len(root_lock)==46 and len(probe_lock)==33 and not (probe_lock-root_lock), "external lock drift")
    result = read(HERE/"probe-5/stdout.txt")
    require(result["status"]=="passed-scoped" and result["profile_admitted"] is False, "scope overclaimed")
    cases = result["cases"]
    require(len(cases)==8, "case denominator differs")
    compact, sparse = cases[:2]
    require(compact["case"]=="mixed_compact_two_rows" and sparse["case"]=="mixed_sparse_two_rows"
            and compact["wire_bytes"]==sparse["wire_bytes"]
            and all(x>y for x,y in zip(sparse["per_row_resident"],compact["per_row_resident"])), "capacity contrast differs")
    for case in (compact,sparse):
        require(case["identical_entity_values_separate_buffers"] and case["separate_row_and_inner_allocations"]
                and case["queued_bytes_before_receive"]==case["wire_bytes"]*2
                and case["queued_items_before_receive"]==2 and case["queued_bytes_after_receive"]==0
                and case["output_bytes"]==case["wire_bytes"]*2 and case["ack_release_each"]
                and case["complete_only_after_end_and_receipt"], "queue/ack evidence differs")
    by_resource = {case["resource"]:case for case in cases[2:5]}
    require(set(by_resource)=={"QueryWorkspaceBytes","QueueBytes","OutputBytes"}, "quota denominator differs")
    for name, case in by_resource.items():
        require(case["terminal_error"]["code"]=="QUOTA_EXCEEDED" and not case["delivery_complete"]
                and not case["envelope_complete"] and case["workspace_after"]==0 and case["queue_bytes_after"]==0,
                name + " failure terminal differs")
    workspace, queue, output = (by_resource[n] for n in ("QueryWorkspaceBytes","QueueBytes","OutputBytes"))
    require(workspace["row_resident_capacity_bytes"]>workspace["limit"] and workspace["json_count_steps"]==0
            and workspace["output_row_steps"]==0 and workspace["output_bytes_charged"]==0, "workspace phase differs")
    require(queue["full_wire_bytes_independent"]>queue["limit"] and queue["json_count_steps"]>0
            and queue["output_row_steps"]>0 and queue["output_bytes_charged"]==queue["full_wire_bytes_independent"], "queue phase differs")
    require(output["full_wire_bytes_independent"]>output["limit"] and output["json_count_steps"]>0
            and output["output_row_steps"]==0 and output["output_bytes_charged"]==0
            and output["terminal_error"]["details"]["encoded_length_exact"] is False, "output phase differs")
    cancel, missing_end, overflow = cases[5:]
    require(cancel["case"]=="cancel_held_then_ack" and cancel["held_during_cancel"]>0
            and cancel["workspace_after_ack"]==0 and not cancel["delivery_complete"]
            and cancel["unaccounted_downstream_clone_still_alive"], "cancel/held clone differs")
    require(missing_end["case"]=="ack_without_end" and missing_end["receipt_rejected"]
            and not missing_end["delivery_complete"], "end proof differs")
    require(overflow["case"]=="budget_counter_overflow" and overflow["error"]=="QUOTA_EXCEEDED"
            and overflow["original_retained_until_drop"] and overflow["after_drop"]==0
            and "not safely materializable" in overflow["row_capacity_overflow"], "overflow scope differs")
    events = [json.loads(line) for line in (HERE/"probe-5/stderr.txt").read_text(encoding="utf8").splitlines()]
    complete = [x["observation"] for x in events if x["event"]=="case_completed"]
    quotas = [x for x in events if x["event"]=="quota_observed"]
    require(complete==cases and len(quotas)==3, "incremental phase records differ")
    for x in quotas:
        require(x==by_resource[x["resource"]], "quota observation changed")
    prior_failure = read(HERE/"probe-4/record.json")
    require(prior_failure["exit_code"]!=0 and prior_failure["tree_empty_verified"], "prior failure not retained")
    require(identity(HERE/"probe-4/stderr.txt")["sha256"]==prior_failure["stderr_sha256"], "prior failure output changed")
    for label in ("probe-1","probe-3"):
        blocked = read(HERE/(label+"-admission-blocked.json"))
        require(blocked["worker_started"] is False and int(blocked["available_physical_bytes"])<int(blocked["minimum_bytes"]), label+" blocked evidence differs")
    print(json.dumps({"status":"passed-readback-scoped", "cases":len(cases),
        "source_count":len(probe["sources_after"]), "binary_sha256":probe["binary_sha256"],
        "resident_compact":compact["per_row_resident"], "resident_sparse":sparse["per_row_resident"],
        "wire_bytes_per_row":compact["wire_bytes"], "quota_phases":{
            name:{"json_count_steps":x["json_count_steps"],"output_bytes_charged":x["output_bytes_charged"]}
            for name,x in by_resource.items()},
        "prior_failure_and_blocked_runs_retained":True, "profile_admitted":False,
        "limits":["provider and caller copies, allocator overhead and RSS not qualified",
                  "independent oracle's serde buffer is not production transport",
                  "row-size overflow statically checked, budget counter overflow executed",
                  "no SQL, worker or transport profile qualification"]}))


if __name__ == "__main__":
    main()
