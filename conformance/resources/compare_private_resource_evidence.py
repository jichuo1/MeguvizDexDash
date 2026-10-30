#!/usr/bin/env python3
"""Compare scoped private resource fingerprints; persist hashes/counts only."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
COMMIT = "e56db3e9380a60b117e9e65ec5ab3f76ffb61361"
A0_SHA = "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448"
HOST_COMMIT = "8782f43d537c442905123e35af325c412caa5188"
RAW_PARENT = "artifacts/integration/20261028/private-raw-diagnostic-20261028T172024248736Z.json"
RAW_READBACK = "artifacts/integration/20261028/private-raw-diagnostic-20261028T172024248736Z-readback.json"


class CheckFailure(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise CheckFailure(reason)


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def digest_path(path):
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda:stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
        return digest.hexdigest()


def digest_handle(stream):
    stream.seek(0)
    digest = hashlib.sha256()
    for chunk in iter(lambda:stream.read(8 * 1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def read_json(path):
    return json.loads(path.read_bytes())


def canonical_digest(value):
    return digest_bytes(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8"))


def compare_stored_maps(host_map, native_map):
    require(isinstance(host_map, dict) and isinstance(native_map, dict), "RESOURCE_MAP_INVALID")
    require(all(isinstance(k, str) and isinstance(v, str) and len(v) == 64 for k,v in host_map.items())
            and all(isinstance(k, str) and isinstance(v, str) and len(v) == 64 for k,v in native_map.items()),
            "RESOURCE_MAP_VALUE_INVALID")
    names_equal = set(host_map) == set(native_map)
    unequal_values = sum(host_map[name] != native_map[name] for name in set(host_map) & set(native_map))
    require(names_equal and unequal_values == 0, "STORED_RESOURCE_MAPS_DIFFER")


def source_identity(path, commit):
    relative = path.relative_to(ROOT).as_posix()
    git = ["git", "-c", "safe.directory=" + str(ROOT), "show", commit + ":" + relative]
    proc = subprocess.run(git, cwd=ROOT, capture_output=True, check=False)
    require(proc.returncode == 0 and proc.stdout == path.read_bytes(), "PINNED_SOURCE_DRIFT")
    return {"sha256":digest_bytes(proc.stdout), "bytes":len(proc.stdout)}


def inspect_sample(sample, parent_item, back_item):
    version = sample["id"].split("-")[-1]
    a0_dir = ROOT / "artifacts/local/baseline-runs" / ("qualification-20261029-a0-" + version) / "worker"
    certificate_path, evidence_path = a0_dir / "certificate.json", a0_dir / "evidence.json"
    certificate = read_json(certificate_path)
    evidence_raw = evidence_path.read_bytes()
    evidence = json.loads(evidence_raw)
    raw_path = ROOT / back_item["private_raw_directory"] / "stdout.txt"
    raw_bytes = raw_path.read_bytes()
    native = json.loads(raw_bytes)
    expected_sha = sample["sha256"]
    require(certificate["variant"] == "A0" and certificate["complete"] is True
            and certificate["input_sha256"] == expected_sha and certificate["engine_sha256"] == A0_SHA
            and certificate["reference_source_commit"] == HOST_COMMIT and certificate["fallback_count"] == 0
            and certificate["output_fully_materialized"] is True and certificate["more_available"] is False
            and certificate["truncated"] is False and certificate["evidence_sha256"] == digest_bytes(evidence_raw),
            "A0_CERTIFICATE_OR_OUTPUT_IDENTITY_MISMATCH")
    require(parent_item["status"] == "native-raw-calculation-complete"
            and parent_item["job"]["status"] == "completed" and parent_item["job"]["exit_code"] == 0
            and parent_item["job"]["tree_empty_verified"] is True
            and back_item["input"]["sha256"] == parent_item["input"]["sha256"] == expected_sha
            and back_item["stdout"]["sha256"] == parent_item["stdout"]["sha256"] == digest_bytes(raw_bytes)
            and len(raw_bytes) == back_item["stdout"]["bytes"]
            and native["input_content_id"] == "sha256:" + expected_sha and native["operation_status"] == "ok"
            and native["calculation_complete"] is True and native["full_audit_complete"] is False,
            "NATIVE_TERMINAL_OR_OUTPUT_IDENTITY_MISMATCH")
    host_source = ROOT / "artifacts/local/hostlab-reference/tools/hostlab/audit_common.py"
    native_audit = ROOT / "conformance/corpus/hostlab/source-8782f43/native_audit.py"
    require(certificate["tools"]["audit_common.py"] == digest_path(host_source)
            and certificate["tools"]["native_audit.py"] == digest_path(native_audit), "A0_RECIPE_SOURCE_MISMATCH")
    host_map = evidence["resource_fingerprints"]
    native_map = native["resource_fingerprints"]
    compare_stored_maps(host_map, native_map)
    require(len(host_map) == back_item["resource_fingerprints"], "STORED_RESOURCE_COUNT_DIFFERS")
    path = Path(sample["actual_path"]).resolve(strict=True)
    metadata_before = path.stat()
    physical_count, byte_mismatches = 0, 0
    seen = set()
    with path.open("rb") as stream:
        require(digest_handle(stream) == expected_sha, "LIVE_INPUT_HASH_BEFORE_MISMATCH")
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            for member in archive.infolist():
                name = member.filename
                if name != "resources.arsc" and not (name.startswith("res/") and name.endswith(".xml")):
                    continue
                require(name not in seen, "AMBIGUOUS_DUPLICATE_RESOURCE_NAME")
                seen.add(name)
                digest = hashlib.sha256()
                with archive.open(member) as source:
                    for chunk in iter(lambda:source.read(1024 * 1024), b""):
                        digest.update(chunk)
                physical_count += 1
                if digest.hexdigest() != native_map.get(name) or digest.hexdigest() != host_map.get(name):
                    byte_mismatches += 1
        require(digest_handle(stream) == expected_sha, "LIVE_INPUT_HASH_AFTER_MISMATCH")
    metadata_after = path.stat()
    require(metadata_before.st_size == metadata_after.st_size == sample["bytes"]
            and metadata_before.st_mtime_ns == metadata_after.st_mtime_ns, "LIVE_INPUT_METADATA_CHANGED")
    require(seen == set(host_map) and physical_count == len(host_map) and byte_mismatches == 0,
            "INDEPENDENT_ZIP_RESOURCE_BYTES_DIFFER")
    return {"input_id":sample["id"], "input_bytes":sample["bytes"], "input_sha256":expected_sha,
            "a0_certificate_sha256":digest_path(certificate_path), "a0_evidence_sha256":digest_bytes(evidence_raw),
            "a0_business_exit_code":certificate["business_exit_code"],
            "native_raw_stdout_sha256":digest_bytes(raw_bytes), "resource_recipe_source_sha256":digest_path(host_source),
            "resource_entries":physical_count, "stored_maps_same_names_and_values":True,
            "independent_raw_zip_entries_equal":True, "resource_map_canonical_sha256":canonical_digest(host_map),
            "a0_selected_class_records":len(evidence["class_records"]),
            "native_all_class_records":sum(item["class_count"] for item in native["selected_dexes"]),
            "native_all_method_records":sum(item["method_count"] for item in native["selected_dexes"]),
            "source_same_sha256_before_after":True, "scope":"selected decompressed resource bytes only"}


def main():
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = ROOT / "artifacts/integration/20261028" / ("private-resource-comparison-" + stamp + ".json")
    raw_parent = read_json(ROOT / RAW_PARENT)
    back = read_json(ROOT / RAW_READBACK)
    registry = read_json(ROOT / "artifacts/bootstrap/20261028/private-input-acquisition.json")
    report = {"schema_version":"mdd.private-resource-comparison.v1", "created_utc":datetime.now(timezone.utc).isoformat(),
              "status":"running", "native_commit":COMMIT, "a0_sha256":A0_SHA,
              "resource_recipe":"SHA-256 of decompressed resources.arsc and res/*.xml; names and multiplicity checked",
              "full_hostlab_audit_equivalent":False, "method_fingerprints_compared":False,
              "method_boundary":"A0 stores selected individual class recipes; native private diagnostic stores per-DEX aggregate of all classes/methods, so existing outputs cannot be aligned.",
              "performance_qualified":False, "results":[]}
    try:
        require(raw_parent["source_commit"] == back["source_commit"] == COMMIT
                and back["parent_sha256"] == digest_path(ROOT / RAW_PARENT)
                and back["status"] == "passed-native-raw-output-readback", "NATIVE_PARENT_READBACK_MISMATCH")
        report["native_producer_sources"] = {
            "raw_evidence_summary":source_identity(ROOT / "crates/mdd-facts/examples/raw_evidence_summary.rs", COMMIT),
            "raw_fingerprints":source_identity(ROOT / "crates/mdd-facts/src/raw_fingerprints.rs", COMMIT)}
        require(len(registry["inputs"]) == len(raw_parent["results"]) == len(back["results"]) == 2,
                "INPUT_COUNT_MISMATCH")
        for sample in registry["inputs"]:
            parents = [x for x in raw_parent["results"] if x["input_id"] == sample["id"]]
            backs = [x for x in back["results"] if x["input_id"] == sample["id"]]
            require(len(parents) == len(backs) == 1, "INPUT_ID_COLLISION")
            report["results"].append(inspect_sample(sample, parents[0], backs[0]))
        report["status"] = "passed-resource-byte-equivalence-only"
    except Exception as error:
        report["status"] = "failed-or-blocked"
        report["failure"] = {"type":type(error).__name__, "reason":str(error) if isinstance(error, CheckFailure) else "UNEXPECTED_READ_OR_VALIDATION_ERROR"}
        path.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8",newline="\n")
        print(json.dumps({"receipt":path.relative_to(ROOT).as_posix(), "status":report["status"], "failure":report["failure"]}))
        raise
    path.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps({"receipt":path.relative_to(ROOT).as_posix(), "status":report["status"],
                      "counts":[item["resource_entries"] for item in report["results"]],
                      "method_fingerprints_compared":False, "performance_qualified":False}))


if __name__ == "__main__":
    main()
