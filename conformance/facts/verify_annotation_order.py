#!/usr/bin/env python3
"""Check ordered annotations, nulls and duplicate sources against byte oracle and A0."""
import datetime
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import verify_definition_projections as common

ROOT = common.ROOT
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT = ROOT / "artifacts/mdd-026/annotation-order-audit" / STAMP
common.OUT = OUT
FIXTURES = ["tests/fixtures/annotations/generated/annotations-038.dex",
            "tests/fixtures/annotations/generated/bad-parameter-arity.dex"]
RELATIONS = ["annotation_directory_entries", "annotation_set_entries", "annotations", "annotation_elements"]
SORT_KEYS = {"annotation_directory_entries":["file_id", "annotations_off", "entry_kind", "entry_idx"],
             "annotation_set_entries":["file_id", "annotation_set_off", "ordinal", "annotation_off"],
             "annotations":["file_id", "annotation_off"],
             "annotation_elements":["file_id", "annotation_off", "value_off", "depth", "ordinal"]}


def oracle_class():
    path = ROOT / "tests/fixtures/annotations/oracle.py"
    spec = importlib.util.spec_from_file_location("mdd_annotation_order_oracle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Oracle


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def compare_exact(actual, expected):
    common.require(canonical(actual) == canonical(expected), "ordered annotation rows differ")


def validate_types(rows, columns):
    for row in rows:
        common.require(set(row) == {c["name"] for c in columns}, "column set differs")
        for column in columns:
            value = row[column["name"]]
            if value is None:
                common.require(column["nullable"], "unexpected NULL")
            elif column["data_type"] == "UInt32":
                common.require(type(value) is int and 0 <= value <= 0xffffffff, "invalid UInt32")
            elif column["data_type"] == "Int64":
                common.require(isinstance(value, str) and str(int(value)) == value
                               and -(1 << 63) <= int(value) < (1 << 63), "invalid Int64")
            elif column["data_type"] == "Float64":
                common.require(type(value) in [int, float] or value in ["NaN", "Infinity", "-Infinity"], "invalid Float64")
            elif column["data_type"].startswith("Utf8"):
                common.require(isinstance(value, str), "invalid text")
            else:
                raise RuntimeError("unsupported schema type: " + column["data_type"])


def a0_equal(actual, expected, columns):
    common.require(len(actual) == len(expected), "A0 annotation row count differs")
    negative_zero_display_changes = 0
    for a, e in zip(actual, expected):
        for column in columns:
            name, typ = column["name"], column["data_type"]
            x, y = a[name], e[name]
            if y is None:
                common.require(x is None, "A0 NULL differs: " + name)
            elif typ == "Float64":
                common.require(x is not None, "A0 float missing")
                xf, yf = float(x), float(y)
                common.require((math.isnan(xf) and math.isnan(yf)) or xf == yf, "A0 float differs")
                if xf == 0.0 and yf == 0.0 and math.copysign(1.0, xf) != math.copysign(1.0, yf):
                    negative_zero_display_changes += 1
            else:
                common.require(x == str(y), "A0 cell differs: " + name)
    return negative_zero_display_changes


def main():
    common.require(common.A0.is_file() and common.digest(common.A0) == common.A0_SHA, "A0 identity mismatch")
    manifest = json.loads((ROOT / "tests/fixtures/annotations/manifest.json").read_text(encoding="utf-8"))
    fixtures = {item["path"]:item["sha256"] for item in manifest["files"] if item["path"] in FIXTURES}
    common.require(set(fixtures) == set(FIXTURES), "fixture manifest incomplete")
    sources = ["conformance/facts/annotation_order_probe.rs", "conformance/facts/verify_annotation_order.py",
               "conformance/facts/verify_definition_projections.py", "tests/fixtures/annotations/oracle.py",
               "tests/fixtures/annotations/manifest.json", "conformance/manifests/relations.json",
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
    exe = OUT / "annotation_order_probe.exe"
    argv = ["rustc", "--edition=2024", "--crate-name", "mdd_annotation_order_probe", sources[0],
            "-L", "dependency=target/debug/deps", "-o", exe]
    for name in ["mdd_dex", "mdd_facts", "mdd_input", "mdd_types", "serde_json"]:
        common.require(name in libraries, "missing Cargo artifact " + name)
        argv += ["--extern", name + "=" + libraries[name]]
    common.command("compile", argv)
    binary_sha = common.digest(exe)
    schema = json.loads((ROOT / "conformance/manifests/relations.json").read_text(encoding="utf-8"))
    relations = {item["name"]:item["columns"] for item in schema["relations"] if item["name"] in RELATIONS}
    common.require(set(relations) == set(RELATIONS), "relation schema missing")
    Oracle = oracle_class()
    native_good = None
    case_results = []
    for case, path in [("complete", FIXTURES[0]), ("parameter-positions-unknown", FIXTURES[1])]:
        data = (ROOT / path).read_bytes()
        common.require(hashlib.sha256(data).hexdigest() == fixtures[path], "fixture changed")
        expected = Oracle(data).read()
        output = json.loads(common.command("native-" + case, [exe, ROOT / path]))
        occ = output["occurrences"]
        common.require(output["probe_complete"] and output["operation_status"] == "ok" and len(occ) == 2,
                       "native terminal incomplete")
        common.require([item["selected"]["file_id"] for item in occ] == [0, 1], "source numbers differ")
        common.require(len({item["source"]["dex_occurrence_id"] for item in occ}) == 2, "DEX occurrence collapsed")
        for item in occ:
            common.require(item["source"]["content_id"] == "sha256:" + fixtures[path], "source content differs")
            file_id = item["selected"]["file_id"]
            error = item["prototype_positions_error"]
            if case == "parameter-positions-unknown":
                common.require(error is not None and error["code"] == "INCOMPLETE_FACTS"
                               and error["details"]["required_layer"] == "prototype_parameter_annotation_positions"
                               and error["details"]["dex_occurrence_id"] == item["source"]["dex_occurrence_id"],
                               "unknown parameter positions became success or lost source")
            else:
                common.require(error is None, "valid parameter positions unexpectedly incomplete")
            for relation in RELATIONS:
                rows = item["rows"][relation]
                compare_exact(rows, [dict(row, file_id=file_id) for row in expected[relation]])
                validate_types(rows, relations[relation])
        if case == "complete":
            native_good = occ
        case_results.append({"case":case, "fixture":path, "sha256":fixtures[path], "occurrences":2,
                             "row_counts_per_occurrence":{rel:len(expected[rel]) for rel in RELATIONS},
                             "ordered_native_equal_independent_byte_oracle":True,
                             "parameter_positions_unknown":case != "complete"})
    good_path = ROOT / FIXTURES[0]
    a0_results = []
    display_negative_zero_changes = 0
    for relation in RELATIONS:
        columns = relations[relation]
        names = [column["name"] for column in columns]
        expr = [f'''CASE WHEN "{name}" IS NULL THEN 'N' ELSE hex(CAST("{name}" AS TEXT)) END AS "{name}"'''
                for name in names]
        sql = "SELECT " + ",".join(expr) + " FROM " + relation + " ORDER BY " + ",".join(SORT_KEYS[relation])
        raw = common.command("a0-" + relation, [common.A0, "--threads", "1", "query", "--input", good_path,
                                                  "--input", good_path, "--sql", sql])
        rows = common.table(raw, names)
        decoded = [{key:None if value == "N" else bytes.fromhex(value).decode("utf-8", "strict")
                    for key, value in row.items()} for row in rows]
        expected = [row for occurrence in native_good for row in occurrence["rows"][relation]]
        expected.sort(key=lambda row:tuple(row[key] for key in SORT_KEYS[relation]))
        changes = a0_equal(decoded, expected, columns)
        display_negative_zero_changes += changes
        a0_results.append({"relation":relation, "rows":len(decoded), "columns":names,
                           "ordered_values_equal_with_numeric_zero_sign_normalized":True,
                           "negative_zero_display_sign_changes":changes})
    rows = native_good[0]["rows"]["annotation_elements"]
    common.require(len(rows) >= 2 and rows[0]["name_idx"] is not None and rows[1]["name_idx"] is None,
                   "fixture lacks null/order negative controls")
    controls = []
    for label, altered in [("swapped_order", [rows[1], rows[0], *rows[2:]]),
                           ("null_to_zero", [rows[0], dict(rows[1], name_idx=0), *rows[2:]]),
                           ("dropped_row", rows[1:])]:
        try:
            compare_exact(altered, rows)
        except RuntimeError as error:
            common.require(str(error) == "ordered annotation rows differ", "unexpected negative control error")
            controls.append(label)
        else:
            raise RuntimeError("negative control accepted: " + label)
    null_counts = {name:{col["name"]:{"null":sum(row[col["name"]] is None for occurrence in native_good for row in occurrence["rows"][name]),
                                       "non_null":sum(row[col["name"]] is not None for occurrence in native_good for row in occurrence["rows"][name])}
                         for col in relations[name] if col["nullable"]} for name in RELATIONS}
    common.require(all(v["null"] and v["non_null"] for fields in null_counts.values() for v in fields.values()),
                   "nullable column lacks both fixture cases")
    common.require(common.digest(common.A0) == common.A0_SHA and common.digest(exe) == binary_sha, "binary changed")
    common.require(all(common.digest(ROOT / path) == sha for path, sha in identities.items()), "source changed")
    common.require(all(common.digest(ROOT / path) == sha for path, sha in fixtures.items()), "fixture changed")
    report = {"schema_version":"mdd.annotation-order-differential.v1", "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status":"passed-native-ordered-facts-a0-normalized-observations", "task_complete_proven":False, "profile_admitted":False,
              "a0_sha256":common.A0_SHA, "native_binary_sha256":binary_sha, "sources":identities,
              "cases":case_results, "a0_multi_input":a0_results, "nullable_column_sample_counts":null_counts,
              "a0_negative_zero_display_sign_changes":display_negative_zero_changes, "negative_controls_rejected":controls,
              "limits":["Native API returns ordered rows; A0 independently orders explicitly by declared query keys.",
                        "A0 numeric comparison deliberately normalizes zero sign; sign changes are separately counted and not declared bitwise equal.",
                        "Parameter-position Unknown remains INCOMPLETE_FACTS; encoded annotation rows can still be complete.",
                        "Small synthetic DEX only; no production compatibility provider, full HostLab or performance qualification."]}
    (OUT / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"path":str(OUT.relative_to(ROOT)), "relations":len(RELATIONS),
                      "a0_rows":sum(row["rows"] for row in a0_results), "negative_zero_changes":display_negative_zero_changes,
                      "negative_controls":len(controls), "task_complete_proven":False}))


if __name__ == "__main__":
    main()
