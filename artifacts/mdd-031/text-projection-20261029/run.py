"""Differential observation: fixed engines, real synthetic DEX, and structured SQL parameters."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
RUN = OUT / "runs" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
FIXTURE = ROOT / "tests/fixtures/generated/strings-mutf8-035.dex"
FIXTURE_SHA = "4deab5f75b23c118b170005d89a6ebc0d18d894383280253e70de0507d260f35"
ENGINES = {
    "A0": (Path(r"D:\Bilibili_Innocent_Lab\tools\hostlab\vendor\dexsql\0.1.0\dexsql-windows-amd64.exe"), "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448"),
    "A1": (ROOT / "artifacts/local/baseline-engines/A1-0.1.1-windows/dexsql-windows-amd64.exe", "602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6"),
}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(label, argv, required=True):
    folder = RUN / label
    folder.mkdir(parents=True, exist_ok=True)
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    begin = time.monotonic()
    try:
        run = subprocess.run([str(arg) for arg in argv], cwd=ROOT, capture_output=True, timeout=90)
        status, stdout, stderr = run.returncode, run.stdout, run.stderr
    except subprocess.TimeoutExpired as error:
        status, stdout, stderr = None, error.stdout or b"", error.stderr or b""
    (folder / "stdout.txt").write_bytes(stdout)
    (folder / "stderr.txt").write_bytes(stderr)
    record = {"argv": [str(arg) for arg in argv], "started_utc": start, "elapsed_seconds": time.monotonic() - begin,
              "exit_code": status, "timed_out": status is None, "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
              "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "scope": "synthetic development corpus; not performance"}
    (folder / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    if required:
        require(status == 0, label + " failed; original output retained")
    return status, stdout


def table(data, names):
    lines = [line for line in data.decode("utf-8").splitlines() if line.startswith("|")]
    rows = [[cell.strip() for cell in line.strip("|").split("|")] for line in lines]
    require(rows and rows[0] == names, "unexpected table header")
    require(all(len(row) == len(names) for row in rows), "unexpected table width")
    return [dict(zip(names, row)) for row in rows[1:]]


def text(cell):
    require(cell["type"] == "text", "text cell type differs")
    value = cell["value"]
    return b"".join(unit.to_bytes(2, "little") for unit in value["utf16"]).decode("utf-16-le", errors="surrogatepass")


def main():
    require(digest(FIXTURE) == FIXTURE_SHA, "fixture identity differs")
    for name, (path, expected) in ENGINES.items():
        require(digest(path) == expected, name + " identity differs")
    source_paths = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "tests/fixtures/references/oracle.py",
                    "artifacts/mdd-031/text-projection-20261029/probe.rs", "artifacts/mdd-031/text-projection-20261029/run.py"]
    for package in ["mdd-sql", "mdd-query", "mdd-session", "mdd-facts", "mdd-dex", "mdd-input", "mdd-types"]:
        source_paths.append(f"crates/{package}/Cargo.toml")
        source_paths += [str(p.relative_to(ROOT)).replace("\\", "/") for p in sorted((ROOT / "crates" / package / "src").rglob("*.rs"))]
    identities = {name: digest(ROOT / name) for name in source_paths}
    _, data = command("build", ["cargo", "build", "-p", "mdd-sql", "--example", "sql_bridge_probe", "--locked", "--offline", "--jobs", "1", "--message-format=json"])
    libraries = {}
    for line in data.splitlines():
        event = json.loads(line)
        if event.get("reason") == "compiler-artifact":
            files = [name for name in event.get("filenames", []) if name.endswith(".rlib")]
            if len(files) == 1:
                libraries[event["target"]["name"]] = files[0]
    exe = RUN / "probe.exe"
    args = ["rustc", "--edition=2024", "--crate-name", "mdd_sql_text_observer", OUT / "probe.rs", "-L", "dependency=target/debug/deps", "-o", exe]
    for name in ["mdd_dex", "mdd_facts", "mdd_input", "mdd_sql", "mdd_types", "serde_json"]:
        require(name in libraries, "missing Cargo artifact " + name)
        args += ["--extern", name + "=" + libraries[name]]
    command("compile", args)
    exe_sha = digest(exe)
    _, data = command("native", [exe, FIXTURE])
    observed = json.loads(data)
    require(observed["probe_complete"] and observed["fixture_sha256"] == FIXTURE_SHA, "native terminal or input differs")
    spec = importlib.util.spec_from_file_location("mdd_text_oracle", ROOT / "tests/fixtures/references/oracle.py")
    oracle_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle_module)
    class Oracle(oracle_module.Oracle):
        def instructions(self, words, base):
            return []
    oracle = Oracle(FIXTURE.read_bytes())
    require(len(oracle.units) == 7, "fixture string count differs")
    labels = ["empty", "nul", "ascii", "cjk", "high", "supplementary", "low"]
    dialects = {}
    for dialect in observed["dialects"]:
        name = dialect["dialect"]
        rows = dialect["source_query"]["rows"]
        require(len(rows) == len(oracle.units), name + " source rows incomplete")
        details = []
        for index, row in enumerate(rows):
            require(int(row[0]["value"]) == index, "ordinal mismatch")
            require(row[1]["value"]["utf16"] == oracle.units[index], "source UTF16 mismatch")
            require(row[1]["value"]["original_mutf8"] is None, "source bytes unexpectedly claimed by text projection")
            require(bytes(row[2]["value"]["bytes"]).hex() == oracle.raw_strings[index], "raw source mismatch")
            require(text(row[3]).lower() == oracle.raw_strings[index], "hex raw mismatch")
            standard = b"".join(unit.to_bytes(2, "little") for unit in oracle.units[index]).decode("utf-16-le", errors="surrogatepass").encode("utf-8", errors="surrogatepass").hex()
            expected = standard if name == "native" else oracle.raw_strings[index]
            require(text(row[4]).lower() == expected, name + " text projection mismatch")
            details.append({"index":index, "case":labels[index], "utf16":oracle.units[index], "raw_hex":oracle.raw_strings[index], "text_hex":text(row[4]).lower()})
        for index, case in enumerate(dialect["parameters"]):
            require(case["case"] == labels[index] and len(case["result"]["rows"]) == 1, "parameter result mismatch")
            cells = case["result"]["rows"][0]
            require(cells[0]["value"]["utf16"] == oracle.units[index] and cells[0]["value"]["original_mutf8"] is None, "parameter text mismatch")
            require(text(cells[1]).lower() == details[index]["text_hex"] and text(cells[2]).lower() == oracle.raw_strings[index], "parameter hex mismatch")
        nulls = dialect["null_query"]["rows"]
        require(len(nulls) == 1 and nulls[0][0]["type"] == "null" and text(nulls[0][1]) == "", "NULL mismatch")
        dialects[name] = details
    require(set(dialects) == {"native", "010", "011"}, "missing dialect")
    sql = "SELECT hex(CAST(s.string_idx AS TEXT)) AS idx_hex,hex(CAST(s.value AS TEXT)) AS value_hex FROM strings AS s ORDER BY s.string_idx"
    legacy = {}
    for name, (engine, expected_sha) in ENGINES.items():
        _, raw = command(name + "-hex", [engine, "--threads", "1", "query", "--input", FIXTURE, "--sql", sql])
        rows = table(raw, ["idx_hex", "value_hex"])
        decoded = [(int(bytes.fromhex(row["idx_hex"]).decode("ascii")), row["value_hex"].lower()) for row in rows]
        require(decoded == list(enumerate(oracle.raw_strings)), name + " DEX bytes differ")
        status, _ = command(name + "-display", [engine, "--threads", "1", "query", "--input", FIXTURE, "--sql", "SELECT s.string_idx,s.value FROM strings AS s ORDER BY s.string_idx"], required=False)
        legacy[name] = {"binary_sha256":expected_sha, "hex_rows":len(decoded), "hex_equal_dex_mutf8":True, "direct_display_exit_code":status}
    require(digest(exe) == exe_sha and digest(FIXTURE) == FIXTURE_SHA, "binary or input changed")
    require(all(digest(ROOT / path) == sha for path, sha in identities.items()), "source changed during observation")
    require(all(digest(path) == expected for path, expected in ENGINES.values()), "reference engine changed")
    report = {"schema_version":"mdd.sql.text-projection-observation.v1", "status":"passed-scoped-differential", "fixture_sha256":FIXTURE_SHA,
              "native_probe_sha256":exe_sha, "source_sha256":identities, "legacy":legacy, "dialects":dialects,
              "source_and_parameter_cases_per_dialect":7, "null_per_dialect":1, "profile_admitted":False,
              "limits":["Small synthetic DEX and local parameter cases only; no private corpus or performance qualification.",
                        "Source MUTF8 and UTF16 projection remain separate; output TEXT does not claim raw-byte provenance.",
                        "Native unpaired-surrogate output is non-scalar and its byte encoding is not valid standard UTF-8.",
                        "Legacy direct text display is recorded separately from byte-preserving hex; no UTF8 display parity inferred.",
                        "Standalone low-level bridge run; no session/transport qualification."]}
    (RUN / "qualification.json").write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status":report["status"], "path":str(RUN.relative_to(ROOT)), "legacy_engines":list(legacy), "cases_per_dialect":7, "profile_admitted":False}))


if __name__ == "__main__":
    main()
