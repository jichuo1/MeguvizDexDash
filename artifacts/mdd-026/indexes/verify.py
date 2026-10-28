"""Offline receipt readback and deliberately corrupt oracle payload controls."""
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
from reproduce import ROOT, BASE, digest, owned_sources, require, verify_probe

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def main():
    result_path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else sorted((BASE / "runs").glob("*/result.json"))[-1]
    require(result_path.is_relative_to(BASE), "readback result must stay in the assigned artifact directory")
    result = read(result_path)
    directory = result_path.parent
    require(result["passed"] is True and result["profiles_admitted"] is False, "qualification flags changed")
    require(result["source_sha256"] == owned_sources(), "current owned source differs from tested source")
    require(result["lock_sha256"] == digest(ROOT / "Cargo.lock"), "current lock differs from tested lock")
    hand_path = ROOT / "tests/fixtures/indexes/expected.json"
    require(result["hand_oracle_sha256"] == digest(hand_path), "hand oracle changed")
    require(result["independent_matrix_sha256"] == digest(ROOT / "conformance/facts/required-columns.json"), "independent matrix changed")
    hand = read(hand_path)
    require(digest(ROOT / hand["input"]) == hand["sha256"], "source fixture changed")
    for label in ["toolchain", "cargo", "facts-tests", "utf16-oracle-probe", "strict-clippy"]:
        receipt = read(directory / (label + ".json"))
        require(receipt["exit_code"] == 0, "nonzero receipt")
        require(receipt["lock_before_sha256"] == result["lock_sha256"] == receipt["lock_after_sha256"], "command lock mismatch")
        for stream in ["stdout", "stderr"]:
            require(digest(directory / (label + "." + stream + ".txt")) == receipt[stream + "_sha256"], "raw command stream hash mismatch")
    output = (directory / "utf16-oracle-probe.stdout.txt").read_text(encoding="utf-8")
    payloads = [json.loads(line.split("INDEX_ORACLE_JSON=", 1)[1]) for line in output.splitlines() if "INDEX_ORACLE_JSON=" in line]
    require(len(payloads) == 1, "missing/excess raw probe payload")
    probe = read(directory / "utf16-native.json")
    require(probe == payloads[0], "parsed native artifact differs from raw consumed output")
    require(verify_probe(probe, hand) == result["checks"], "oracle result summary mismatch")
    mutations = []
    bad = copy.deepcopy(probe); bad["rows"][0]["locals"] = [999]; mutations.append(bad)
    bad = copy.deepcopy(probe); bad["selected_dex_occurrences"][1] = bad["selected_dex_occurrences"][0]; mutations.append(bad)
    bad = copy.deepcopy(probe); bad["rows"].pop(); mutations.append(bad)
    bad = copy.deepcopy(probe); bad["columns"][0]["nullable"] = not bad["columns"][0]["nullable"]; mutations.append(bad)
    bad = copy.deepcopy(probe); bad["columns"][0]["assembled_projection"] = not bad["columns"][0]["assembled_projection"]; mutations.append(bad)
    bad = copy.deepcopy(probe); bad["source_content_ids"][0] = "sha256:wrong"; mutations.append(bad)
    for bad in mutations:
        try:
            verify_probe(bad, hand)
        except RuntimeError:
            continue
        raise RuntimeError("a deliberate broken oracle payload was accepted")
    stderr = (directory / "facts-tests.stderr.txt").read_text(encoding="utf-8")
    match = re.search(r"Running unittests.*?\((target[^\r\n)]+)\)", stderr)
    binary = None
    if match:
        path = (ROOT / match[1]).resolve()
        require(path.is_relative_to(ROOT / "target") and path.is_file(), "native test binary path is invalid")
        binary = {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size, "sha256": digest(path), "identity_observed_at_readback": True}
    verification = {"schema_version": "mdd.index-receipt-readback.v1", "passed": True, "result": result_path.relative_to(ROOT).as_posix(), "result_sha256": digest(result_path), "raw_streams_verified": 10, "deliberately_invalid_oracle_payloads_rejected": len(mutations), "test_binary": binary, "source_sha256": owned_sources(), "claims_unchanged": result["not_claimed"]}
    (directory / "readback.json").write_text(json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "readback": (directory / "readback.json").relative_to(ROOT).as_posix(), "raw_streams_verified": 10, "invalid_controls_rejected": len(mutations)}))

if __name__ == "__main__":
    main()
