#!/usr/bin/env python3
"""Compare scalar/non-scalar native text facts and A0 byte display."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time
import verify_definition_projections as common

ROOT = common.ROOT
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT = ROOT / "artifacts/mdd-026/type-text-audit" / STAMP
common.OUT = OUT
CASES = {
    "type-names": ("tests/fixtures/references/generated/type-names-035.dex", "9d4d2cfebd4ac275fe508004cd7efd29b307c855671e716da6e02955ab93774f"),
    "definitions": ("tests/fixtures/definitions/generated/definitions-035.dex", "4e8f9e8deedf44c8793e10d99f2614e0bed705dcac617c0d74137e7b2bd459cc"),
    "mutf8": ("tests/fixtures/generated/strings-mutf8-035.dex", "4deab5f75b23c118b170005d89a6ebc0d18d894383280253e70de0507d260f35"),
    "nonscalar": ("tests/fixtures/references/generated/nonscalar-string-035.dex", "d2bc2a79ed9d2304a3ffeb9bc0c762fccc5460019a280ab923901b84ddd9510a"),
}


def oracle_class():
    spec = importlib.util.spec_from_file_location("mdd_type_text_oracle", ROOT / "tests/fixtures/references/oracle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    class Oracle(module.Oracle):
        def instructions(self, words, base):
            return []  # This check observes only strings/types, never instruction semantics.
    return Oracle


def java_name(descriptor):
    dimensions = len(descriptor) - len(descriptor.lstrip("["))
    base = descriptor[dimensions:]
    primitive = {"Z":"boolean", "B":"byte", "S":"short", "C":"char", "I":"int", "J":"long",
                 "F":"float", "D":"double", "V":"void"}
    common.require(base in primitive or (base.startswith("L") and base.endswith(";")), "unhandled descriptor")
    name = primitive[base] if base in primitive else base[1:-1].replace("/", ".")
    return name + "[]" * dimensions


def from_units(units):
    raw = b"".join(value.to_bytes(2, "little") for value in units)
    try:
        return {"status":"scalar", "value":raw.decode("utf-16-le", "strict")}
    except UnicodeDecodeError:
        return {"status":"non_scalar"}


def compare_strings(native, oracle):
    common.require(len(native) == len(oracle.units), "string count differs")
    for index, entry in enumerate(native):
        fact, text = entry["fact"], entry["fact"]["data"]["text"]
        common.require(fact["data"]["string_idx"] == index and fact["entity"]["local_index"] == index,
                       "string coordinate differs")
        common.require(text["utf16_units"] == oracle.units[index]
                       and bytes(text["raw_mutf8"]).hex() == oracle.raw_strings[index], "lossless string differs")
        common.require(entry["strict_utf8"] == from_units(oracle.units[index]), "strict scalar outcome differs")


def command_error(label, argv):
    folder = OUT / label
    folder.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    begin = time.monotonic()
    result = subprocess.run([str(x) for x in argv], cwd=ROOT, capture_output=True, timeout=90)
    (folder / "stdout.txt").write_bytes(result.stdout)
    (folder / "stderr.txt").write_bytes(result.stderr)
    record = {"argv":[str(x) for x in argv], "started_utc":started,
              "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "elapsed_seconds":time.monotonic()-begin, "exit_code":result.returncode,
              "stdout_sha256":hashlib.sha256(result.stdout).hexdigest(),
              "stderr_sha256":hashlib.sha256(result.stderr).hexdigest(), "scope":"bounded negative conformance"}
    (folder / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return result


def main():
    common.require(common.A0.is_file() and common.digest(common.A0) == common.A0_SHA, "A0 identity mismatch")
    sources = ["conformance/facts/type_text_probe.rs", "conformance/facts/verify_type_text_atoms.py",
               "conformance/facts/verify_definition_projections.py", "tests/fixtures/references/oracle.py",
               "tests/fixtures/manifest.json", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
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
            files = [name for name in artifact.get("filenames", []) if name.endswith(".rlib")]
            if len(files) == 1:
                libraries[artifact["target"]["name"]] = files[0]
    exe = OUT / "type_text_probe.exe"
    argv = ["rustc", "--edition=2024", "--crate-name", "mdd_type_text_probe", sources[0],
            "-L", "dependency=target/debug/deps", "-o", exe]
    for name in ["mdd_dex", "mdd_facts", "mdd_input", "mdd_types", "serde_json"]:
        common.require(name in libraries, "missing Cargo artifact " + name)
        argv += ["--extern", name + "=" + libraries[name]]
    common.command("compile", argv)
    binary_sha = common.digest(exe)
    Oracle = oracle_class()
    observations = []
    controls = []
    for name, (path, sha) in CASES.items():
        data = (ROOT / path).read_bytes()
        common.require(hashlib.sha256(data).hexdigest() == sha, "fixture identity mismatch")
        oracle = Oracle(data)
        native = json.loads(common.command("native-" + name, [exe, ROOT / path]))
        common.require(native["probe_complete"] and native["operation_status"] == "ok"
                       and native["source"]["content_id"] == "sha256:" + sha, "native terminal/source differs")
        compare_strings(native["strings"], oracle)
        if name == "mutf8":
            for label in ["changed_utf16_unit", "changed_raw_mutf8", "non_scalar_as_empty"]:
                altered = json.loads(json.dumps(native["strings"]))
                if label == "changed_utf16_unit":
                    altered[1]["fact"]["data"]["text"]["utf16_units"] = []
                elif label == "changed_raw_mutf8":
                    altered[1]["fact"]["data"]["text"]["raw_mutf8"] = [0]
                else:
                    altered[4]["strict_utf8"] = {"status":"scalar", "value":""}
                try:
                    compare_strings(altered, oracle)
                except RuntimeError as error:
                    common.require(str(error) in ["lossless string differs", "strict scalar outcome differs"],
                                   "unexpected mutation error")
                    controls.append(label)
                else:
                    raise RuntimeError("negative control accepted: " + label)
        common.require([x["data"]["descriptor"] for x in native["types"]] == oracle.types, "type descriptors differ")
        for index, item in enumerate(native["types"]):
            common.require(item["data"]["type_idx"] == index and item["entity"]["local_index"] == index
                           and item["entity"]["dex_occurrence_id"] == native["source"]["dex_occurrence_id"]
                           and item["descriptor_string"]["dex_occurrence_id"] == native["source"]["dex_occurrence_id"],
                           "type coordinates/source differ")
            dimensions = len(oracle.types[index]) - len(oracle.types[index].lstrip("["))
            common.require(item["data"]["shape"]["array_dimensions"] == dimensions, "array dimensions differ")
        a0_values = None
        if name in ["mutf8", "nonscalar"]:
            sql = 'SELECT hex(CAST(s.string_idx AS TEXT)) AS idx_hex,hex(CAST(s.value AS TEXT)) AS value_hex FROM strings AS s ORDER BY s.string_idx'
            rows = common.table(common.command("a0-strings-" + name, [common.A0, "--threads", "1", "query",
                                                                       "--input", ROOT / path, "--sql", sql]), ["idx_hex", "value_hex"])
            a0_values = [(int(bytes.fromhex(row["idx_hex"]).decode("ascii")), row["value_hex"].lower()) for row in rows]
            common.require(a0_values == list(enumerate(oracle.raw_strings)), "A0 text bytes differ from fixture MUTF8")
        type_rows = None
        if name in ["type-names", "definitions"]:
            columns = ["file_id", "type_idx", "descriptor", "java_name"]
            expressions = [f'''CASE WHEN "{col}" IS NULL THEN 'N' ELSE hex(CAST("{col}" AS TEXT)) END AS "{col}"''' for col in columns]
            sql = "SELECT " + ",".join(expressions) + " FROM types AS t ORDER BY t.type_idx"
            rows = common.table(common.command("a0-types-" + name, [common.A0, "--threads", "1", "query",
                                                                      "--input", ROOT / path, "--sql", sql]), columns)
            decoded = [{key:None if value == "N" else bytes.fromhex(value).decode("utf-8") for key, value in row.items()} for row in rows]
            expected = [{"file_id":"0", "type_idx":str(index), "descriptor":desc, "java_name":java_name(desc)}
                        for index, desc in enumerate(oracle.types)]
            common.require(decoded == expected, "A0 type name differs")
            type_rows = len(decoded)
        non_scalar = [index for index, item in enumerate(native["strings"]) if item["strict_utf8"]["status"] == "non_scalar"]
        observations.append({"case":name, "fixture":path, "sha256":sha, "strings":len(oracle.units),
                             "types":len(oracle.types), "a0_type_rows":type_rows,
                             "a0_mutf8_byte_rows":len(a0_values) if a0_values is not None else None,
                             "non_scalar_indices":non_scalar, "native_utf16_and_raw_mutf8_equal_byte_oracle":True})
    manifest = json.loads((ROOT / "tests/fixtures/manifest.json").read_text(encoding="utf-8"))
    negatives = []
    for id, expected_code in [("bad-checksum", "INVALID_INPUT"), ("unsupported-041", "UNSUPPORTED_CAPABILITY")]:
        matching = [item for item in manifest["files"] if item["id"] == id]
        common.require(len(matching) == 1, "negative fixture missing")
        fixture = matching[0]
        common.require(common.digest(ROOT / fixture["path"]) == fixture["sha256"], "negative fixture changed")
        process = command_error("native-negative-" + id, [exe, ROOT / fixture["path"]])
        observed = json.loads(process.stdout)
        common.require(process.returncode != 0 and observed["operation_status"] == "error"
                       and observed["error"]["code"] == expected_code, "wrong negative terminal: " + id)
        negatives.append({"id":id, "path":fixture["path"], "sha256":fixture["sha256"],
                          "exit_code":process.returncode, "actual_error":observed["error"]})
    common.require(common.digest(common.A0) == common.A0_SHA and common.digest(exe) == binary_sha, "binary changed")
    common.require(all(common.digest(ROOT / path) == sha for path, sha in identities.items()), "source changed")
    common.require(all(common.digest(ROOT / path) == sha for path, sha in CASES.values()), "fixture changed")
    report = {"schema_version":"mdd.type-text-atoms-observation.v1", "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status":"passed-limited-raw-observations", "task_complete_proven":False, "profile_admitted":False,
              "a0_sha256":common.A0_SHA, "native_binary_sha256":binary_sha, "sources":identities,
              "cases":observations, "native_negative_terminals":negatives, "negative_controls_rejected":controls,
              "limits":["Java names are produced by the conformance byte oracle; a production types.java_name relation is not provided.",
                        "A0 hex(CAST(value AS TEXT)) matches the observed DEX MUTF8 bytes; that is not evidence of valid standard UTF-8 text.",
                        "Unpaired UTF16 surrogate is preserved as native code units and rejected by strict scalar conversion; no replacement character is substituted.",
                        "Small hand fixtures only; no production compatibility admission or full HostLab claim."]}
    (OUT / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"path":str(OUT.relative_to(ROOT)), "cases":len(observations),
                      "negative_terminals":len(negatives), "negative_controls":len(controls), "task_complete_proven":False}))


if __name__ == "__main__":
    main()
