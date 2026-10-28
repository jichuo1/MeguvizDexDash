#!/usr/bin/env python3
"""Compare real definition row APIs against the fixed A0 on a tiny fixture."""
import collections
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "artifacts/mdd-026/new-audit/definition-projections"
FIXTURE = "tests/fixtures/definitions/generated/definitions-035.dex"
A0 = Path(r"D:\Bilibili_Innocent_Lab\tools\hostlab\vendor\dexsql\0.1.0\dexsql-windows-amd64.exe")
A0_SHA = "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448"
FIXTURE_SHA = "4e8f9e8deedf44c8793e10d99f2614e0bed705dcac617c0d74137e7b2bd459cc"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(label, argv):
    folder = OUT / label
    folder.mkdir(parents=True, exist_ok=True)
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    begin = time.monotonic()
    result = subprocess.run([str(arg) for arg in argv], cwd=ROOT, capture_output=True, timeout=90)
    (folder / "stdout.txt").write_bytes(result.stdout)
    (folder / "stderr.txt").write_bytes(result.stderr)
    record = {"argv": [str(arg) for arg in argv], "started_utc": start,
              "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "elapsed_seconds": time.monotonic() - begin, "exit_code": result.returncode,
              "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
              "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
              "scope": "tiny development conformance; not performance"}
    (folder / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    require(result.returncode == 0, label + " failed; raw output retained")
    return result.stdout


def table(raw, columns):
    lines = [line for line in raw.decode("utf-8").splitlines() if line.startswith("|")]
    require(lines, "A0 produced no table header")
    parsed = [[value.strip() for value in line.strip("|").split("|")] for line in lines]
    require(parsed[0] == columns, "A0 table columns differ")
    require(all(len(row) == len(columns) for row in parsed), "invalid table width")
    return [dict(zip(columns, row)) for row in parsed[1:]]


def encode(value):
    if value is None:
        return "N"
    require(isinstance(value, (str, int)) and not isinstance(value, bool), "unexpected fixture value type")
    require(str(value).isascii(), "probe only qualifies ASCII fixture projections")
    return str(value).encode("utf-8").hex().upper()


def canonical(rows):
    return collections.Counter(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows)


def compare_rows(actual, rows, columns, file_id):
    require(all(set(row) == set(columns) for row in rows), "native column mismatch")
    expected = [dict(row, file_id=encode(file_id)) for row in actual]
    observed = [{column: encode(row[column]) for column in columns} for row in rows]
    require(canonical(observed) == canonical(expected), "native/A0 row mismatch")


def main():
    require(A0.is_file() and digest(A0) == A0_SHA, "fixed A0 identity mismatch")
    fixture = ROOT / FIXTURE
    require(digest(fixture) == FIXTURE_SHA, "fixture identity mismatch")
    source_paths = ["conformance/facts/definition_projection_probe.rs", "conformance/facts/verify_definition_projections.py",
                    "conformance/manifests/relations.json", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
    for package in ["mdd-dex", "mdd-input", "mdd-types", "mdd-facts"]:
        source_paths.append(f"crates/{package}/Cargo.toml")
        source_paths.extend(path.relative_to(ROOT).as_posix()
                            for path in sorted((ROOT / "crates" / package / "src").rglob("*.rs")))
    sources = {path: digest(ROOT / path) for path in source_paths}
    build_output = command("build", ["cargo", "build", "-p", "mdd-facts", "--lib", "--jobs", "1",
                                     "--locked", "--offline", "--message-format=json"])
    libraries = {}
    for line in build_output.splitlines():
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact":
            found = [name for name in item.get("filenames", []) if name.endswith(".rlib")]
            if len(found) == 1:
                libraries[item["target"]["name"]] = found[0]
    executable = OUT / "definition_projection_probe.exe"
    argv = ["rustc", "--edition=2024", "--crate-name", "mdd_definition_projection_probe",
            source_paths[0], "-L", "dependency=target/debug/deps", "-o", executable]
    for name in ["mdd_dex", "mdd_facts", "mdd_input", "mdd_types", "serde_json"]:
        require(name in libraries, "missing Cargo artifact: " + name)
        argv.extend(["--extern", name + "=" + libraries[name]])
    command("compile", argv)
    binary_sha = digest(executable)
    native = json.loads(command("native", [executable, fixture]))
    occurrences = native["selected_occurrences"]
    require(native["probe_complete"] and native["operation_status"] == "ok" and len(occurrences) == 2,
            "missing complete native terminal")
    require([x["selected"]["file_id"] for x in occurrences] == [0, 1], "ordered file IDs differ")
    require(len({x["selected"]["dex_occurrence_id"] for x in occurrences}) == 2, "DEX occurrences collapsed")
    require(len({x["selected"]["source_occurrence_id"] for x in occurrences}) == 2, "source occurrences collapsed")
    require(all(x["selected"]["content_id"] == "sha256:" + FIXTURE_SHA for x in occurrences), "content identity mismatch")
    schemas = json.loads((ROOT / "conformance/manifests/relations.json").read_text(encoding="utf-8"))
    names = ["class_interfaces", "class_fields", "class_methods"]
    relations = {item["name"]: item for item in schemas["relations"] if item["name"] in names}
    require(set(relations) == set(names), "required relation schema absent")
    results = []
    for name in names:
        columns = [item["name"] for item in relations[name]["columns"]]
        expressions = [f'''CASE WHEN "{col}" IS NULL THEN 'N' ELSE hex(CAST("{col}" AS TEXT)) END AS "{col}"'''
                       for col in columns]
        sql = "SELECT " + ",".join(expressions) + " FROM " + name
        actual = table(command("a0-" + name, [A0, "--threads", "1", "query", "--input", fixture, "--sql", sql]), columns)
        require(actual, "expected non-empty fixture relation: " + name)
        for occurrence in occurrences:
            file_id = occurrence["selected"]["file_id"]
            rows = occurrence[name]
            compare_rows(actual, rows, columns, file_id)
        results.append({"relation": name, "columns": columns, "a0_rows": len(actual),
                        "native_rows_per_occurrence": [len(x[name]) for x in occurrences],
                        "single_occurrence_a0_multiset_equal": True,
                        "second_occurrence_compared_with_file_id_rebound": True})
    rows = occurrences[0]["class_interfaces"]
    columns = [item["name"] for item in relations["class_interfaces"]["columns"]]
    a0_rows = table((OUT / "a0-class_interfaces/stdout.txt").read_bytes(), columns)
    controls = []
    for label, altered in [
        ("wrong_file_id", [dict(rows[0], file_id=99), *rows[1:]]),
        ("unexpected_null", [dict(rows[0], interface_descriptor=None), *rows[1:]]),
        ("missing_row", rows[1:]),
    ]:
        try:
            compare_rows(a0_rows, altered, columns, 0)
        except RuntimeError as exc:
            require(str(exc) == "native/A0 row mismatch", "unexpected negative-control failure")
            controls.append(label)
        else:
            raise RuntimeError("negative control accepted: " + label)
    require(digest(A0) == A0_SHA and digest(fixture) == FIXTURE_SHA, "input changed during probe")
    require(digest(executable) == binary_sha, "native binary changed during probe")
    require(all(digest(ROOT / path) == sha for path, sha in sources.items()), "source changed during probe")
    report = {"schema_version":"mdd.definition-projections-differential.v1", "task":"MDD-026",
              "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status":"passed-small-fixture-only", "task_complete_proven":False, "profile_admitted":False,
              "a0_sha256":A0_SHA, "fixture_sha256":FIXTURE_SHA, "sources":sources,
              "native_binary_sha256":binary_sha, "results":results, "negative_controls_rejected":controls,
              "limits":["A0 single DEX rows compared as multisets; ordering is not proven.",
                        "Second occurrence is checked against the single-input A0 rows with file_id rebound, not against an A0 multi-input execution.",
                        "Other fields, input forms, NULL boundaries, query transport and full HostLab workload are not qualified."]}
    (OUT / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"relations":len(results), "columns":sum(len(r["columns"]) for r in results),
                      "two_source_occurrences":True, "negative_controls":len(controls), "task_complete_proven":False}))


if __name__ == "__main__":
    main()
