#!/usr/bin/env python3
"""Compare real multi-input A0 IDs and native occurrence/pool identities."""
import collections
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile
import verify_definition_projections as common

ROOT = common.ROOT
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT = ROOT / "artifacts/mdd-026/cross-dex-audit" / STAMP
common.OUT = OUT
FIXTURES = {
    "classic": ("tests/fixtures/references/generated/classic-035.dex", "076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8"),
    "shared": ("tests/fixtures/references/generated/shared-code-035.dex", "22eb2d4020f172334a99f5c75538af5f2b3e80673adb11803b368cc68aaec0ab"),
}


def oracle_class():
    path = ROOT / "tests/fixtures/references/oracle.py"
    spec = importlib.util.spec_from_file_location("mdd_cross_dex_independent_oracle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Oracle


def table_query(columns, relation, order):
    expr = [f'''CASE WHEN {sql} IS NULL THEN 'N' ELSE hex(CAST({sql} AS TEXT)) END AS "{name}"'''
            for name, sql in columns]
    return "SELECT " + ",".join(expr) + " " + relation + " ORDER BY " + order


def decode_rows(raw, names):
    rows = common.table(raw, names)
    return [{key:None if value == "N" else bytes.fromhex(value).decode("utf-8", "strict")
             for key, value in row.items()} for row in rows]


def compare_join(actual, expected):
    common.require(actual == expected, "A0 JOIN rows, ordering or multiplicity differ")


def main():
    common.require(common.A0.is_file() and common.digest(common.A0) == common.A0_SHA, "A0 identity mismatch")
    content = {}
    for name, (path, sha) in FIXTURES.items():
        content[name] = (ROOT / path).read_bytes()
        common.require(hashlib.sha256(content[name]).hexdigest() == sha, "fixture changed: " + name)
    sources = ["conformance/facts/cross_dex_identity_probe.rs", "conformance/facts/verify_cross_dex_identity.py",
               "conformance/facts/verify_definition_projections.py", "tests/fixtures/references/oracle.py",
               "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
    for package in ["mdd-dex", "mdd-input", "mdd-types", "mdd-facts"]:
        sources.append(f"crates/{package}/Cargo.toml")
        sources.extend(path.relative_to(ROOT).as_posix() for path in sorted((ROOT / "crates" / package / "src").rglob("*.rs")))
    identities = {path:common.digest(ROOT / path) for path in sources}
    build = common.command("build", ["cargo", "build", "-p", "mdd-facts", "--lib", "--jobs", "1",
                                     "--locked", "--offline", "--message-format=json"])
    libraries = {}
    for line in build.splitlines():
        artifact = json.loads(line)
        if artifact.get("reason") == "compiler-artifact":
            filenames = [name for name in artifact.get("filenames", []) if name.endswith(".rlib")]
            if len(filenames) == 1:
                libraries[artifact["target"]["name"]] = filenames[0]
    exe = OUT / "cross_dex_identity_probe.exe"
    argv = ["rustc", "--edition=2024", "--crate-name", "mdd_cross_dex_probe", sources[0],
            "-L", "dependency=target/debug/deps", "-o", exe]
    for name in ["mdd_dex", "mdd_facts", "mdd_input", "mdd_types", "serde_json"]:
        common.require(name in libraries, "missing Cargo artifact " + name)
        argv += ["--extern", name + "=" + libraries[name]]
    common.command("compile", argv)
    binary_sha = common.digest(exe)
    apk = OUT / "synthetic-same-content.apk"
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as archive:
        for entry in ["classes.dex", "classes2.dex"]:
            info = zipfile.ZipInfo(entry, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, content["classic"])
    apk_sha = common.digest(apk)
    classic, shared = [ROOT / FIXTURES[name][0] for name in ["classic", "shared"]]
    cases = {
        "duplicate-raw-input": (["dex", classic, "dex", classic], [classic, classic], ["classic", "classic"]),
        "two-distinct-raw": (["dex", classic, "dex", shared], [classic, shared], ["classic", "shared"]),
        "same-content-multidex-apk": (["apk", apk], [apk], ["classic", "classic"]),
    }
    dex_columns = [("file_id", "d.file_id"), ("string_pool_id", "d.string_pool_id"),
                   ("source_path", "d.source_path"), ("entry_name", "d.entry_name")]
    join_columns = [("file_id", "d.file_id"), ("string_pool_id", "d.string_pool_id"),
                    ("string_idx", "s.string_idx"), ("value", "s.value")]
    dex_sql = table_query(dex_columns, "FROM dex_files d", "d.file_id")
    join_sql = table_query(join_columns, "FROM dex_files d JOIN strings s ON s.string_pool_id=d.string_pool_id",
                           "d.file_id,s.string_idx")
    Oracle = oracle_class()
    observations = []
    controls = []
    for name, (native_args, a0_inputs, expected_inputs) in cases.items():
        native = json.loads(common.command("native-" + name, [exe, *native_args]))
        common.require(native["probe_complete"] and native["operation_status"] == "ok", "native terminal incomplete")
        occ = native["occurrences"]
        common.require(len(occ) == len(expected_inputs) == 2, "occurrence count mismatch")
        common.require([x["selected"]["file_id"] for x in occ] == [0, 1], "native file IDs out of order")
        common.require(len({x["source"]["dex_occurrence_id"] for x in occ}) == 2, "native DEX occurrences collapsed")
        for item, fixture_name in zip(occ, expected_inputs):
            reference = Oracle(content[fixture_name])
            common.require(item["source"]["content_id"] == "sha256:" + FIXTURES[fixture_name][1], "native content mismatch")
            common.require([x["data"]["text"]["utf16_units"] for x in item["strings"]] == reference.units,
                           "native UTF16 string order mismatch")
            common.require([bytes(x["data"]["text"]["raw_mutf8"]).hex() for x in item["strings"]] == reference.raw_strings,
                           "native MUTF8 bytes mismatch")
            common.require([x["data"]["string_idx"] for x in item["strings"]] == list(range(len(reference.units))),
                           "native string coordinates mismatch")
            common.require(all(x["entity"]["dex_occurrence_id"] == item["source"]["dex_occurrence_id"]
                               and x["string_pool_id"] == item["pool"]["string_pool_id"] for x in item["strings"]),
                           "native entity binding mismatch")
        input_args = [arg for path in a0_inputs for arg in ["--input", path]]
        dex_rows = decode_rows(common.command("a0-dex-files-" + name,
                               [common.A0, "--threads", "1", "query", *input_args, "--sql", dex_sql]),
                               [column[0] for column in dex_columns])
        join_rows = decode_rows(common.command("a0-join-" + name,
                                [common.A0, "--threads", "1", "query", *input_args, "--sql", join_sql]),
                                [column[0] for column in join_columns])
        common.require(len(dex_rows) == 2, "A0 occurrence count differs")
        common.require([int(row["file_id"]) for row in dex_rows] == [0, 1], "A0 ordering/numbering differs")
        expected_entry = ["classes.dex", "classes2.dex"] if name.endswith("apk") else [path.name for path in a0_inputs]
        expected_source = [str(apk), str(apk)] if name.endswith("apk") else [str(path) for path in a0_inputs]
        common.require([row["entry_name"] for row in dex_rows] == expected_entry, "A0 physical member names differ")
        common.require([row["source_path"] for row in dex_rows] == expected_source, "A0 source paths differ")
        expected_rows = []
        for row, fixture_name in zip(dex_rows, expected_inputs):
            reference = Oracle(content[fixture_name])
            common.require(all(text.isascii() for text in reference.strings), "fixture is not ASCII")
            expected_rows.extend({"file_id":row["file_id"], "string_pool_id":row["string_pool_id"],
                                  "string_idx":str(index), "value":text}
                                 for index, text in enumerate(reference.strings))
        compare_join(join_rows, expected_rows)
        if name == "duplicate-raw-input":
            variants = [
                ("wrong_pool", [dict(join_rows[0], string_pool_id="999"), *join_rows[1:]]),
                ("missing_row", join_rows[1:]),
                ("wrong_value", [dict(join_rows[0], value="altered"), *join_rows[1:]]),
            ]
            for label, altered in variants:
                try:
                    compare_join(altered, expected_rows)
                except RuntimeError as error:
                    common.require(str(error) == "A0 JOIN rows, ordering or multiplicity differ", "unexpected control failure")
                    controls.append(label)
                else:
                    raise RuntimeError("negative control accepted: " + label)
        common.require(len({row["string_pool_id"] for row in dex_rows}) == 2,
                       "A0 pools unexpectedly shared between occurrences")
        physical_pool_ids = [x["pool"]["string_pool_id"] for x in occ]
        if expected_inputs[0] == expected_inputs[1]:
            common.require(physical_pool_ids[0] == physical_pool_ids[1], "equal contents should share physical pool identity")
        else:
            common.require(physical_pool_ids[0] != physical_pool_ids[1], "distinct contents collapsed physical identity")
        source_ids = [x["source"]["source_occurrence_id"] for x in occ]
        common.require((source_ids[0] == source_ids[1]) == name.endswith("apk"), "physical source identity mismatch")
        observations.append({"case":name, "a0_dex_rows":dex_rows, "a0_join_row_count":len(join_rows),
                             "a0_pool_ids":[row["string_pool_id"] for row in dex_rows],
                             "native_distinct_dex_occurrences":True,
                             "native_physical_pool_ids_equal":physical_pool_ids[0] == physical_pool_ids[1],
                             "native_same_source_occurrence":source_ids[0] == source_ids[1],
                             "ordered_a0_join_matches_independent_string_oracle":True,
                             "native_string_coordinates_and_raw_mutf8_match_oracle":True})
    common.require(common.digest(apk) == apk_sha and common.digest(common.A0) == common.A0_SHA
                   and common.digest(exe) == binary_sha, "binary/input changed during run")
    common.require(all(common.digest(ROOT / path) == sha for path, sha in identities.items()), "source changed")
    common.require(all(common.digest(ROOT / path) == sha for path, sha in FIXTURES.values()), "fixture changed")
    report = {"schema_version":"mdd.cross-dex-identity-observation.v1", "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status":"passed-small-multi-input-observations", "task_complete_proven":False, "profile_admitted":False,
              "a0_sha256":common.A0_SHA, "probe_binary_sha256":binary_sha, "synthetic_apk_sha256":apk_sha,
              "sources":identities, "cases":observations, "negative_controls_rejected":controls,
              "limits":["A0 and native are observed independently; no production compatibility pool mapping is implemented here.",
                        "Three bounded synthetic cases, ASCII strings and standard DEX only; no 041 shared data, private inputs or performance.",
                        "A0 result JOIN is fully consumed; this is not the HostLab full audit or a profile admission."]}
    (OUT / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"path":str(OUT.relative_to(ROOT)), "cases":len(observations),
                      "a0_join_rows":sum(row["a0_join_row_count"] for row in observations),
                      "negative_controls":len(controls), "task_complete_proven":False}))


if __name__ == "__main__":
    main()
