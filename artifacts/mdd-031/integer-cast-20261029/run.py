"""Replay exact frozen A0/A1 CAST observations, distinguishing value and DTO type."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
RUN = HERE / "runs" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
REFERENCE = ROOT / "artifacts/mdd-031-audit/integer-cast-observations/run-20261028T174032300709Z"
OLD_HELPER = ROOT / "artifacts/mdd-031/text-projection-20261029/run.py"
spec = importlib.util.spec_from_file_location("mdd_text_observer", OLD_HELPER)
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
old.RUN = RUN


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def reference_cases(engine, kind, expected_sha):
    path = REFERENCE / (engine + "-" + kind) / (engine + ".observations.json")
    require(digest(path) == expected_sha, "reference observation hash changed")
    report = json.loads(path.read_text(encoding="utf-8"))
    require(report["client_context_exited"] is True, "reference process not closed")
    out = {}
    for case in report["cases"]:
        require(case["close"]["body"].get("closed") is True, "reference dataset not closed")
        response = case["statements"][0]["response"]
        require(not response["is_error"], "reference request error")
        statement = response["body"]["statements"][0]
        require(statement["total_rows"] == 1 and not statement["truncated"] and statement["next_offset"] is None, "reference result incomplete")
        out[case["id"]] = {"sql":case["statements"][0]["sql"],"cell":statement["rows"][0][0]}
    final = report["active_dataset_after_all_cases"]["body"]
    require(not final["datasets"] and final["usage"]["datasets"] == 0 and final["usage"]["input_bytes"] == 0, "reference dataset leak")
    return out


def value(cell):
    if cell["type"] == "null": return None
    require(cell["type"] in {"i64", "u64", "int64", "uint64"}, "unexpected integer cell")
    return int(cell["value"])


def main():
    reference_summary = json.loads((REFERENCE / "summary.json").read_text(encoding="utf-8"))
    source_paths = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "artifacts/mdd-031/integer-cast-20261029/probe.rs", "artifacts/mdd-031/integer-cast-20261029/run.py"]
    for package in ["mdd-sql", "mdd-query", "mdd-session", "mdd-facts", "mdd-dex", "mdd-input", "mdd-types"]:
        source_paths.append(f"crates/{package}/Cargo.toml")
        source_paths += [str(p.relative_to(ROOT)).replace("\\", "/") for p in sorted((ROOT / "crates" / package / "src").rglob("*.rs"))]
    sources = {path:digest(ROOT / path) for path in source_paths}
    _, data = old.command("build", ["cargo", "build", "-p", "mdd-sql", "--example", "sql_bridge_probe", "--locked", "--offline", "--jobs", "1", "--message-format=json"])
    libraries = {}
    for line in data.splitlines():
        event = json.loads(line)
        if event.get("reason") == "compiler-artifact":
            files = [name for name in event.get("filenames", []) if name.endswith(".rlib")]
            if len(files) == 1: libraries[event["target"]["name"]] = files[0]
    exe = RUN / "probe.exe"
    args = ["rustc", "--edition=2024", "--crate-name", "mdd_sql_integer_cast_observer", HERE / "probe.rs", "-L", "dependency=target/debug/deps", "-o", exe]
    for name in ["mdd_dex", "mdd_facts", "mdd_input", "mdd_sql", "mdd_types", "serde_json"]:
        require(name in libraries, "missing Cargo artifact " + name)
        args += ["--extern", name + "=" + libraries[name]]
    old.command("compile", args)
    binary_sha = digest(exe)
    _, data = old.command("candidate", [exe, ROOT])
    candidate = json.loads(data)
    require(candidate["probe_complete"] and not candidate["profile_admitted"], "candidate terminal")
    records = {(record["variant"],record["kind"]):record for record in reference_summary["records"]}
    require(len(records) == 4, "reference record set")
    comparisons = []
    for dialect in candidate["dialects"]:
        engine = {"010":"A0","011":"A1"}[dialect["dialect"]]
        for kind, key in [("literals", "literal_cases"),("dex", "dex_cases")]:
            ref = reference_cases(engine, kind, records[(engine,kind)]["observations_sha256"])
            actual = {case["id"]:case for case in dialect[key]}
            require(set(actual) == set(ref), "case identity mismatch")
            type_differences = []
            for name, case in actual.items():
                result = case["result"]
                require(result["calculation_complete"] and len(result["rows"]) == 1 and len(result["rows"][0]) == 1, "candidate result incomplete")
                if kind == "literals": require(case["sql"] == ref[name]["sql"], "literal SQL changed")
                else: require(case["sql"].replace("native_strings", "strings") == ref[name]["sql"], "DEX SQL changed beyond relation mapping")
                observed_cell, reference_cell = result["rows"][0][0], ref[name]["cell"]
                require(value(observed_cell) == value(reference_cell), "integer value mismatch: " + name)
                normalized = {"i64":"int64","u64":"uint64","null":"null"}[observed_cell["type"]]
                if normalized != reference_cell["type"]:
                    type_differences.append({"id":name,"reference":reference_cell["type"],"candidate":normalized})
            comparisons.append({"engine":engine,"kind":kind,"cases":len(actual),"integer_values_equal":True,
                                "dto_type_differences":type_differences})
    require(all(digest(ROOT / path) == sha for path,sha in sources.items()), "source changed")
    require(digest(exe) == binary_sha, "candidate binary changed")
    report = {"schema_version":"mdd.sql.integer-cast-observation.v1","status":"passed-value-only",
              "candidate_binary_sha256":binary_sha,"source_sha256":sources,"reference_summary_sha256":digest(REFERENCE / "summary.json"),
              "reference_readback_sha256":digest(REFERENCE / "readback.json"),"comparisons":comparisons,
              "profiles_admitted":False,"limits":["NativeV1 strict conversion unchanged; float-to-integer and SQL affinity remain separate.",
              "Equal integer values are not complete DTO type equivalence; recorded type mismatches block compatibility qualification.",
              "Small synthetic DEX and literal corpus only; no real HostLab or performance claim."]}
    (RUN / "qualification.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":report["status"],"path":str(RUN.relative_to(ROOT)),"cases":sum(x["cases"] for x in comparisons),"dto_type_differences":sum(len(x["dto_type_differences"]) for x in comparisons),"profiles_admitted":False}))


if __name__ == "__main__":
    main()
