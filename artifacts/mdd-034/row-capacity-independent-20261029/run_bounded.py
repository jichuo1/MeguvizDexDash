#!/usr/bin/env python3
"""Run a fresh, bounded independent build/probe without editing other processes."""
from datetime import datetime, timezone
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = ROOT / "artifacts/local/row-capacity-independent-20261029-target"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    paths = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "rust-toolchain.toml",
             HERE / "Cargo.toml", HERE / "Cargo.lock", HERE / "src/main.rs",
             ROOT / "tests/fixtures/generated/minimal-035.dex"]
    paths += sorted(p for p in (ROOT / "crates").rglob("*") if p.is_file() and (p.suffix == ".rs" or p.name == "Cargo.toml"))
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in paths}


class Memory(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [(n, ctypes.c_ulonglong) for n in
        ("total", "available", "page_total", "page_available", "virtual_total", "virtual_available", "extended")]


def validate_build_identity(current, build, binary_sha256):
    if (build.get("job_status") != "completed" or build.get("exit_code") != 0
        or build.get("tree_empty_verified") is not True or build.get("sources_unchanged") is not True):
        raise ValueError("build record is not complete and stable")
    if current != build.get("sources_after") or build.get("sources_before") != build.get("sources_after"):
        raise ValueError("probe sources differ from the completed build")
    if not binary_sha256 or binary_sha256 != build.get("binary_sha256"):
        raise ValueError("probe binary differs from the completed build")


def main():
    if len(sys.argv) not in (3, 4) or sys.argv[1] not in ("build", "probe"):
        raise SystemExit("expected build|probe, fresh record label, optional probe build label")
    name, label = sys.argv[1:3]
    build_label = sys.argv[3] if len(sys.argv) == 4 else "build-1"
    if name == "build" and len(sys.argv) != 3:
        raise ValueError("build must not specify a previous build")
    if not label or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label):
        raise ValueError("record label must be lowercase and simple")
    if not build_label or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in build_label):
        raise ValueError("build label must be lowercase and simple")
    folder = HERE / label
    before = sources()
    binary = TARGET / "debug/mdd-row-capacity-independent.exe"
    if name == "probe":
        try:
            build = json.loads((HERE / build_label / "record.json").read_text(encoding="utf8"))
            validate_build_identity(before, build, sha(binary) if binary.is_file() else None)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            output = HERE / (label + "-identity-blocked.json")
            with output.open("x", encoding="utf8") as stream:
                json.dump({"reason":str(error), "worker_started":False,
                           "scope":"source and binary identity admission"}, stream, indent=2)
                stream.write("\n")
            raise
    mem = Memory(); mem.length = ctypes.sizeof(mem)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
        raise RuntimeError("physical-memory observation unavailable")
    if mem.available < 3 * 1024**3:
        output = HERE / (label + "-admission-blocked.json")
        with output.open("x", encoding="utf8") as stream:
            json.dump({"available_physical_bytes": str(mem.available), "minimum_bytes": str(3*1024**3),
                       "worker_started": False, "scope": "development resource admission"}, stream, indent=2)
        raise RuntimeError("insufficient observed memory for bounded independent validation")
    cargo = shutil.which("cargo")
    if not cargo: raise RuntimeError("cargo missing")
    argv = ([cargo, "build", "--locked", "--offline", "--jobs", "1", "--manifest-path", str(HERE / "Cargo.toml")]
            if name == "build" else [str(TARGET / "debug/mdd-row-capacity-independent.exe")])
    env = {key:value for key,value in os.environ.items() if not any(x in key.upper() for x in ("TOKEN","SECRET","PASSWORD","API_KEY"))}
    env["CARGO_TARGET_DIR"] = str(TARGET)
    helper = ROOT / "artifacts/mdd-005/preparation-20261028/windows_job.py"
    orchestration_before = {p.relative_to(ROOT).as_posix(): sha(p) for p in [Path(__file__).resolve(), helper]}
    spec = importlib.util.spec_from_file_location("owned_job", helper); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    start = datetime.now(timezone.utc).isoformat()
    result = module.run_job(argv, folder, cwd=ROOT, env=env, timeout_seconds=240 if name=="build" else 45,
                            memory_bytes=2*1024**3, affinity_mask=15, max_processes=16)
    after = sources()
    orchestration_after = {p.relative_to(ROOT).as_posix(): sha(p) for p in [Path(__file__).resolve(), helper]}
    report = {"argv":argv, "started_utc":start, "finished_utc":datetime.now(timezone.utc).isoformat(),
              "available_physical_bytes_before":str(mem.available), "sources_before":before, "sources_after":after,
              "sources_unchanged":before==after, "orchestration_before":orchestration_before,
              "orchestration_after":orchestration_after, "orchestration_unchanged":orchestration_before==orchestration_after,
              "exit_code":result["exit_code"], "job_status":result["status"],
              "reason":result["reason"], "tree_empty_verified":result["tree_empty_verified"],
              "stdout_sha256":sha(folder/"stdout.txt"), "stderr_sha256":sha(folder/"stderr.txt"),
              "supervisor_sha256":sha(folder/"supervisor.json"), "binary_sha256":sha(binary) if binary.exists() else None,
              "bound_build_record": (HERE / build_label / "record.json").relative_to(ROOT).as_posix() if name == "probe" else None,
              "bound_build_record_sha256": sha(HERE / build_label / "record.json") if name == "probe" else None,
              "scope":"local bounded independent validation; not a performance measurement"}
    with (folder / "record.json").open("x", encoding="utf8") as stream:
        json.dump(report,stream,indent=2); stream.write("\n")
    print(json.dumps({"record":str(folder/"record.json"),"exit_code":result["exit_code"],
                      "tree_empty_verified":result["tree_empty_verified"],"sources_unchanged":before==after,
                      "orchestration_unchanged":orchestration_before==orchestration_after}))
    return 0 if result["status"]=="completed" and result["tree_empty_verified"] and before==after and orchestration_before==orchestration_after else 1


if __name__ == "__main__":
    raise SystemExit(main())
