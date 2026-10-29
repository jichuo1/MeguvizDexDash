#!/usr/bin/env python3
"""Negative controls for probe admission; never launches the heavy probe."""
import copy
import importlib.util
import json
from pathlib import Path
import runpy
import sys

HERE = Path(__file__).resolve().parent
runner = runpy.run_path(str(HERE / "run_bounded.py"))


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def rejected(current, build, binary, expected):
    try:
        runner["validate_build_identity"](current, build, binary)
    except ValueError as error:
        require(expected in str(error), "unexpected rejection: " + str(error))
        return
    raise RuntimeError("negative control was admitted: " + expected)


def main():
    build_label = sys.argv[1] if len(sys.argv) == 2 else "build-1"
    if not build_label or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in build_label):
        raise ValueError("invalid build label")
    build = json.loads((HERE / build_label / "record.json").read_text(encoding="utf8"))
    current = runner["sources"]()
    binary = runner["TARGET"] / "debug/mdd-row-capacity-independent.exe"
    binary_sha = runner["sha"](binary) if binary.is_file() else None
    try:
        runner["validate_build_identity"](current, build, binary_sha)
        actual_admitted = True
        actual_reason = None
    except ValueError as error:
        actual_admitted = False
        actual_reason = str(error)
    stable = copy.deepcopy(build["sources_after"])
    runner["validate_build_identity"](stable, build, build["binary_sha256"])
    changed = copy.deepcopy(stable)
    changed["crates/mdd-query/src/executor.rs"] = "0" * 64
    rejected(changed, build, build["binary_sha256"], "probe sources differ")
    rejected(stable, build, "0" * 64, "probe binary differs")
    rejected(stable, build, None, "probe binary differs")
    failed = copy.deepcopy(build); failed["tree_empty_verified"] = False
    rejected(stable, failed, build["binary_sha256"], "build record is not complete")
    drift = copy.deepcopy(build); drift["sources_before"]["Cargo.lock"] = "0" * 64
    rejected(stable, drift, build["binary_sha256"], "probe sources differ")

    # Exercise the runner's real pre-launch path with controlled fault injection;
    # no source or binary file is modified and no Job is started.
    spec = importlib.util.spec_from_file_location("independent_runner_admission_test", HERE / "run_bounded.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    original_argv, original_sources, original_sha = sys.argv, module.sources, module.sha
    try:
        bad = copy.deepcopy(stable); bad["crates/mdd-query/src/executor.rs"] = "0" * 64
        module.sources = lambda: bad
        sys.argv = ["run_bounded.py", "probe", "identity-negative-source-v3", build_label]
        try:
            module.main()
        except ValueError as error:
            require("probe sources differ" in str(error), "unexpected integrated source failure")
        else:
            raise RuntimeError("integrated source mismatch started a worker")
        module.sources = lambda: stable
        module.sha = lambda path: "0" * 64 if path == binary else original_sha(path)
        sys.argv = ["run_bounded.py", "probe", "identity-negative-binary-v3", build_label]
        try:
            module.main()
        except ValueError as error:
            require("probe binary differs" in str(error), "unexpected integrated binary failure")
        else:
            raise RuntimeError("integrated binary mismatch started a worker")
    finally:
        sys.argv, module.sources, module.sha = original_argv, original_sources, original_sha
    for label in ("identity-negative-source-v3", "identity-negative-binary-v3"):
        blocked = json.loads((HERE / (label + "-identity-blocked.json")).read_text(encoding="utf8"))
        require(blocked["worker_started"] is False and not (HERE / label).exists(), "blocked worker appeared")
    print(json.dumps({"negative_controls_rejected":7, "actual_current_identity_admitted":actual_admitted,
                      "actual_current_identity_reason":actual_reason,
                      "worker_started":False, "scope":"identity admission only; no row probe"}))


if __name__ == "__main__":
    main()
