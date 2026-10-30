"""Recompute the recorded text projection comparison from saved raw evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUN = Path(__file__).resolve().parent / "runs/20261028T170439632106Z"
FIXTURE = ROOT / "tests/fixtures/generated/strings-mutf8-035.dex"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded_mutf8(units):
    output = bytearray()
    for unit in units:
        if unit == 0:
            output.extend((0xc0, 0x80))
        elif unit <= 0x7f:
            output.append(unit)
        elif unit <= 0x7ff:
            output.extend((0xc0 | (unit >> 6), 0x80 | (unit & 63)))
        else:
            output.extend((0xe0 | (unit >> 12), 0x80 | ((unit >> 6) & 63), 0x80 | (unit & 63)))
    return output.hex()


def text(cell):
    require(cell["type"] == "text", "expected typed text")
    return b"".join(unit.to_bytes(2, "little") for unit in cell["value"]["utf16"]).decode("utf-16-le", "surrogatepass")


def table(raw, header):
    lines = [line for line in raw.decode("utf-8").splitlines() if line.startswith("|")]
    rows = [[cell.strip() for cell in line.strip("|").split("|")] for line in lines]
    require(rows and rows[0] == header, "unexpected legacy table header")
    require(all(len(row) == len(header) for row in rows), "legacy table width mismatch")
    return rows[1:]


def verify_native(observed, oracle):
    require(observed["probe_complete"] and len(observed["dialects"]) == 3, "probe incomplete")
    actual_names = set()
    for dialect in observed["dialects"]:
        name = dialect["dialect"]
        require(name not in actual_names and name in {"native", "010", "011"}, "dialect mismatch")
        actual_names.add(name)
        source = dialect["source_query"]
        require(source["calculation_complete"] and not source["profiles_admitted"], "source terminal mismatch")
        require(len(source["rows"]) == len(oracle.units) == len(dialect["parameters"]) == 7, "source rows truncated")
        for i, row in enumerate(source["rows"]):
            units, raw = oracle.units[i], oracle.raw_strings[i]
            require(raw == encoded_mutf8(units), "fixture encoding mismatch")
            require(row[0]["type"] == "u64" and int(row[0]["value"]) == i, "source index mismatch")
            require(row[1]["type"] == "text" and row[1]["value"]["utf16"] == units and row[1]["value"]["original_mutf8"] is None, "source text mismatch")
            require(row[2]["type"] == "dex_mutf8" and bytes(row[2]["value"]["bytes"]).hex() == raw, "source raw mismatch")
            require(text(row[3]).lower() == raw, "raw hex mismatch")
            native_bytes = b"".join(unit.to_bytes(2, "little") for unit in units).decode("utf-16-le", "surrogatepass").encode("utf-8", "surrogatepass").hex()
            expected = native_bytes if name == "native" else raw
            require(text(row[4]).lower() == expected, "cast text hex mismatch")
            param = dialect["parameters"][i]["result"]
            require(param["calculation_complete"] and len(param["rows"]) == 1, "parameter truncated")
            cells = param["rows"][0]
            require(cells[0]["value"]["utf16"] == units and cells[0]["value"]["original_mutf8"] is None, "parameter UTF16 mismatch")
            require(text(cells[1]).lower() == expected and text(cells[2]).lower() == raw, "parameter hex mismatch")
        null = dialect["null_query"]
        require(null["calculation_complete"] and len(null["rows"]) == 1 and null["rows"][0][0]["type"] == "null" and text(null["rows"][0][1]) == "", "null mismatch")
    require(actual_names == {"native", "010", "011"}, "missing dialect")


def main():
    result = json.loads((RUN / "qualification.json").read_text(encoding="utf-8"))
    require(result["status"] == "passed-scoped-differential" and not result["profile_admitted"], "incorrect scope")
    require(sha(FIXTURE.read_bytes()) == result["fixture_sha256"], "fixture identity mismatch")
    for source, expected in result["source_sha256"].items():
        require(sha((ROOT / source).read_bytes()) == expected, "source identity mismatch: " + source)
    for label in ["build", "compile", "native", "A0-hex", "A0-display", "A1-hex", "A1-display"]:
        folder = RUN / label
        record = json.loads((folder / "record.json").read_text(encoding="utf-8"))
        require(record["exit_code"] == 0 and not record["timed_out"], label + " did not finish")
        for stream in ("stdout", "stderr"):
            require(sha((folder / (stream + ".txt")).read_bytes()) == record[stream + "_sha256"], label + " " + stream + " hash mismatch")
    spec = importlib.util.spec_from_file_location("mdd_text_oracle_readback", ROOT / "tests/fixtures/references/oracle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    class Oracle(module.Oracle):
        def instructions(self, words, base):
            return []
    oracle = Oracle(FIXTURE.read_bytes())
    observed = json.loads((RUN / "native/stdout.txt").read_text(encoding="utf-8"))
    verify_native(observed, oracle)
    legacy = {}
    for name in ("A0", "A1"):
        hex_rows = table((RUN / (name + "-hex") / "stdout.txt").read_bytes(), ["idx_hex", "value_hex"])
        actual = [(int(bytes.fromhex(row[0]).decode("ascii")), row[1].lower()) for row in hex_rows]
        require(actual == list(enumerate(oracle.raw_strings)), name + " hex rows differ")
        displays = table((RUN / (name + "-display") / "stdout.txt").read_bytes(), ["string_idx", "value"])
        require(len(displays) == 7 and [int(row[0]) for row in displays] == list(range(7)), name + " display rows incomplete")
        require(displays[1][1] == "\\u{0}" and displays[4][1] == "\ufffd" and displays[6][1] == "\ufffd", name + " display observation differs")
        legacy[name] = {"complete_hex_rows":7, "complete_display_rows":7, "nul_display":"\\u{0}",
                        "isolated_surrogate_display":"U+FFFD", "cast_text_hex_keeps_raw_mutf8":True}
    negatives = []
    for name in ("wrong_raw", "wrong_utf16", "missing_row"):
        altered = copy.deepcopy(observed)
        rows = altered["dialects"][1]["source_query"]["rows"]
        if name == "wrong_raw": rows[1][2]["value"]["bytes"] = [0]
        elif name == "wrong_utf16": rows[4][1]["value"]["utf16"] = [0xfffd]
        else: rows.pop()
        try:
            verify_native(altered, oracle)
        except RuntimeError:
            negatives.append(name)
        else:
            raise RuntimeError("negative control accepted: " + name)
    binary = RUN / "probe.exe"
    binary_verified = binary.is_file() and sha(binary.read_bytes()) == result["native_probe_sha256"]
    require(not binary.is_file() or binary_verified, "probe binary mismatch")
    report = {"schema_version":"mdd.sql.text-projection-readback.v1", "status":"passed", "fixture_sha256":result["fixture_sha256"],
              "readback_sha256":sha(Path(__file__).read_bytes()), "source_identity_count":len(result["source_sha256"]),
              "all_saved_command_hashes_verified":True, "native_probe_binary_verified_if_present":binary_verified,
              "dialects":3, "source_and_parameter_vectors_per_dialect":7, "legacy":legacy, "negative_controls_rejected":negatives,
              "limits":["Small synthetic corpus, no HostLab or performance qualification.",
                        "Legacy CLI display replaces unpaired surrogates and escapes NUL; its byte-preserving hex is a separate observation.",
                        "Native unpaired-surrogate output is not valid standard UTF-8; raw MUTF8 is kept in a separate typed value."]}
    (RUN / "readback.json").write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({"status":"passed", "legacy":legacy, "negative_controls":negatives}))


if __name__ == "__main__":
    main()
