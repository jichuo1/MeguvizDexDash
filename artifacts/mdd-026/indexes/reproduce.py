"""Bounded native checks plus independent UTF16 oracle; explicit gates survive -O.

The hand JSON is never generated from native output. Each invocation appends fresh
raw receipts; no historical failure is overwritten.
"""
from pathlib import Path
import datetime
import hashlib
import json
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
BASE = Path(__file__).resolve().parent

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def owned_sources():
    paths = [ROOT / "crates/mdd-facts/src/coverage.rs"]
    paths += sorted((ROOT / "crates/mdd-facts/src/indexes").glob("*.rs"))
    return {p.relative_to(ROOT).as_posix(): digest(p) for p in paths}

def run(directory, label, arguments):
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    before_lock = digest(ROOT / "Cargo.lock")
    result = subprocess.run(arguments, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, env={**os.environ, "CARGO_BUILD_JOBS": "2"})
    (directory / (label + ".stdout.txt")).write_bytes(result.stdout)
    (directory / (label + ".stderr.txt")).write_bytes(result.stderr)
    receipt = {"command": arguments, "started_utc": started, "exit_code": result.returncode, "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(), "lock_before_sha256": before_lock, "lock_after_sha256": digest(ROOT / "Cargo.lock")}
    (directory / (label + ".json")).write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    require(result.returncode == 0, label + " failed; retain raw receipt")
    require(receipt["lock_before_sha256"] == receipt["lock_after_sha256"], "lock changed during command; repeat for an immutable receipt")
    return result.stdout.decode("utf-8", errors="strict")

def verify_probe(probe, hand):
    require(len(probe["rows"]) == 219, "expected 0/1/2-code-unit patterns in three predicates")
    identities = probe["selected_dex_occurrences"]
    require(len(identities) == 2 and len(set(identities)) == 2, "logical occurrences were deduplicated")
    require(probe["source_content_ids"] == ["sha256:" + hand["sha256"]] * 2, "fixture content identity mismatch")
    patterns = [[]] + [[left] for left in hand["alphabet"]] + [[left, right] for left in hand["alphabet"] for right in hand["alphabet"]]
    seen = set()
    residuals = 0
    for row in probe["rows"]:
        pattern = row["pattern"]
        key = (row["kind"], tuple(pattern))
        require(key not in seen and pattern in patterns, "duplicate or unknown oracle pattern")
        seen.add(key)
        expected = []
        for local, value in enumerate(hand["ordered_string_pool"]):
            if row["kind"] == "equal":
                matches = value == pattern
            elif row["kind"] == "prefix":
                matches = value[:len(pattern)] == pattern
            elif row["kind"] == "contains":
                matches = any(value[start:start + len(pattern)] == pattern for start in range(len(value) - len(pattern) + 1))
            else:
                raise RuntimeError("unexpected predicate")
            if matches:
                expected.append(local)
        require(row["locals"] == expected * 2, "native indexed result disagrees with hand oracle: " + str(key))
        require(row["occurrences"] == [identities[0]] * len(expected) + [identities[1]] * len(expected), "cross-occurrence identity/order mismatch")
        require(row["candidates"] >= len(row["locals"]), "candidate count cannot prove recalled result")
        residuals += row["candidates"] > len(row["locals"])
    require(len(seen) == 219 and residuals > 0, "missing residual filtering cases")
    matrix = json.loads((ROOT / "conformance/facts/required-columns.json").read_text(encoding="utf-8"))
    wanted = {(r["name"], c["name"]): (c["data_type"], c["nullable"], c["production_projection"] != "unassembled_production_relation") for r in matrix["relations"] for c in r["columns"]}
    actual = {(c["relation"], c["column"]): (c["data_type"], c["nullable"], c["assembled_projection"]) for c in probe["columns"]}
    require(len(wanted) == 156 and actual == wanted, "coverage declaration drift from independent 17-relation matrix")
    return {"predicates": len(seen), "distinct_occurrences": 2, "residual_false_positive_candidate_cases": residuals, "columns_checked": len(wanted), "unassembled_projection_columns": sum(not spec[2] for spec in actual.values())}

def main():
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = BASE / "runs" / stamp
    directory.mkdir(parents=True, exist_ok=False)
    before = owned_sources()
    hand_path = ROOT / "tests/fixtures/indexes/expected.json"
    hand = json.loads(hand_path.read_text(encoding="utf-8"))
    require(digest(ROOT / hand["input"]) == hand["sha256"], "hand fixture identity changed")
    run(directory, "toolchain", ["rustc", "-Vv"])
    run(directory, "cargo", ["cargo", "-V"])
    run(directory, "facts-tests", ["cargo", "test", "--locked", "-p", "mdd-facts", "-j", "2", "--", "--test-threads=2"])
    output = run(directory, "utf16-oracle-probe", ["cargo", "test", "--locked", "-p", "mdd-facts", "-j", "2", "indexes::tests::exhaustive_candidate_probe_for_independent_code_unit_oracle", "--", "--exact", "--nocapture", "--test-threads=1"])
    marker = "INDEX_ORACLE_JSON="
    payloads = [line.split(marker, 1)[1] for line in output.splitlines() if marker in line]
    require(len(payloads) == 1, "expected one fully consumed native oracle payload")
    probe = json.loads(payloads[0])
    (directory / "utf16-native.json").write_text(json.dumps(probe, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    checks = verify_probe(probe, hand)
    run(directory, "strict-clippy", ["cargo", "clippy", "--locked", "-p", "mdd-facts", "--all-targets", "-j", "2", "--", "-D", "warnings"])
    after = owned_sources()
    require(before == after, "owned source changed during verification")
    result = {"schema_version": "mdd.index-coverage-conformance.v1", "task": "MDD-026", "passed": True, "checks": checks, "native_atoms_only": True, "profiles_admitted": False, "source_sha256": after, "hand_oracle_sha256": digest(hand_path), "independent_matrix_sha256": digest(ROOT / "conformance/facts/required-columns.json"), "lock_sha256": digest(ROOT / "Cargo.lock"), "raw_receipt_directory": directory.relative_to(ROOT).as_posix(), "python": sys.version, "not_claimed": ["SQL projection admission", "HostLab replacement", "full DEX/ART verification", "private corpus facts", "performance", "G1 admission"]}
    (directory / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "result": (directory / "result.json").relative_to(ROOT).as_posix(), **checks}, ensure_ascii=False))

if __name__ == "__main__":
    main()
