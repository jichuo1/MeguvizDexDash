from pathlib import Path
import hashlib, json
p = Path(__file__).resolve().parent
root = p.parents[2]
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read(name): return json.loads((p / name).read_text(encoding="utf-8"))
r = read("build/record.json")
a = read("build2-admission.json")
s = read("source-before.json")
checks = {
    "build_timed_out_124": r["exit_code"] == 124 and r["timed_out"] is True,
    "owned_tree_empty": r["tree_empty_verified"] is True,
    "retry_blocked_unchanged_3gib": a["admitted"] is False and int(a["minimum_bytes"]) == 3 * 1024**3 and int(a["available_physical_bytes"]) < int(a["minimum_bytes"]),
    "no_retry_job_directory": not (p / "build2").exists(),
    "stdout_hash": digest(p / "build/stdout.txt") == r["stdout_sha256"],
    "stderr_hash": digest(p / "build/stderr.txt") == r["stderr_sha256"],
    "supervisor_hash": digest(p / "build/supervisor.json") == r["supervisor_sha256"],
    "admission_hash": digest(p / "build-admission.json") == r["admission_sha256"],
    "source_manifest_59": len(s["sha256"]) == 59,
    "dependencies_subset_33": s["external_count"] == 33 and s["all_external_subset_of_root"] is True,
}
drift = [name for name, expected in s["sha256"].items() if not (root / name).is_file() or digest(root / name) != expected]
print(json.dumps({"checks": checks, "source_drift_since_sample": drift, "scope": "no independent final binary or queue matrix; no performance claim"}, ensure_ascii=False, indent=2))
raise SystemExit(0 if all(checks.values()) else 1)
