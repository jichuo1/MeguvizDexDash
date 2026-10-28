"""Development evidence collection. Explicit checks survive python -O."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import struct
import zipfile
import math

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "artifacts/mdd-025/manifest"
AAPT = Path(r"C:\Users\Administrator\AppData\Local\Android\Sdk\build-tools\37.0.0\aapt2.exe")
NATIVE = ROOT / "target/debug/examples/manifest_summary.exe"
PUBLIC = ROOT / "artifacts/local/inputs/NewPipe_v0.28.6.apk"
PUBLIC_SHA = "e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58"

def require(condition, message):
    if not condition: raise RuntimeError(message)

def record(name, argv):
    folder = OUT / name; folder.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    begin = time.monotonic()
    result = subprocess.run([str(x) for x in argv], cwd=ROOT, capture_output=True, timeout=180)
    elapsed = time.monotonic() - begin
    (folder / "stdout.txt").write_bytes(result.stdout)
    (folder / "stderr.txt").write_bytes(result.stderr)
    receipt = {"argv": [str(x) for x in argv], "started_utc": started,
               "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "exit_code": result.returncode, "elapsed_seconds": elapsed,
               "measurement_scope": "development validation only, not performance qualification",
               "stdout": {"bytes": len(result.stdout), "sha256": hashlib.sha256(result.stdout).hexdigest()},
               "stderr": {"bytes": len(result.stderr), "sha256": hashlib.sha256(result.stderr).hexdigest()}}
    (folder / "record.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return result

def aapt_tree(text):
    nodes, stack = [], []
    for line in text.splitlines():
        stripped = line.lstrip(); indent = len(line) - len(stripped)
        if stripped.startswith("E: "):
            raw_name = stripped[3:].split(" (line=", 1)[0]
            while stack and stack[-1][0] >= indent: stack.pop()
            if ":" in raw_name: ns, name = raw_name.rsplit(":", 1)
            else: ns, name = None, raw_name
            nodes.append({"namespace_uri": ns, "name": name, "parent": stack[-1][1] if stack else None, "attributes": []})
            stack.append((indent, len(nodes) - 1))
        elif stripped.startswith("A: "):
            match = re.fullmatch(r"A: (.*?)(?:\(0x([0-9a-fA-F]+)\))?=(.*)", stripped)
            require(match is not None and nodes, "unrecognized AAPT attribute: " + line)
            raw_name, rid, rendered = match.groups()
            if ":" in raw_name: ns, name = raw_name.rsplit(":", 1)
            else: ns, name = None, raw_name
            raw = None
            if " (Raw: " in rendered:
                rendered, quoted = rendered.rsplit(" (Raw: ", 1)
                raw = json.loads(quoted[:-1])
            nodes[-1]["attributes"].append({"namespace_uri": ns, "name": name, "resource_id": int(rid, 16) if rid else None,
                                            "rendered": rendered, "raw": raw})
    return nodes

def render(value):
    data, kind = value["raw_data"], value["decoded"]["kind"]
    if kind == "string": return json.dumps(value["decoded"]["value"]["text"], ensure_ascii=False)
    if kind == "int_decimal": return str(value["decoded"]["signed"])
    if kind == "int_hex": return "0x%08x" % data
    if kind == "boolean": return "true" if data else "false"
    if kind == "unresolved_reference": return ("?" if value["decoded"]["attribute"] else "@") + "0x%08x" % data
    if kind == "null": return "@empty" if value["decoded"]["empty"] else "@null"
    if kind == "color": return "#%08x" % data
    if kind == "float_bits":
        number = struct.unpack("<f", struct.pack("<I", data))[0]
        return "nan" if math.isnan(number) else "%f" % number
    if kind in ("dimension", "fraction"):
        mantissa = data & 0xffffff00
        if mantissa & 0x80000000: mantissa -= 0x100000000
        number = mantissa / 256 / [1, 128, 32768, 8388608][(data >> 4) & 3]
        unit = (["px", "dp", "sp", "pt", "in", "mm"] if kind == "dimension" else ["%", "%p"])[data & 15]
        return "%f%s" % (number, unit)
    raise ValueError("independent rendered comparison does not claim type " + kind)

def compare_public(native, text, apk=PUBLIC):
    expected = aapt_tree(text)
    actual = []
    document = native["manifests"][0]["document"]
    for node in document["nodes"]:
        attributes = []
        for attr in node["attributes"]:
            attributes.append({"namespace_uri": attr["name"]["namespace_uri"], "name": attr["name"]["local_name"],
                               "resource_id": attr["resource_id"], "rendered": render(attr["value"]),
                               "raw": attr["raw_value"]["text"] if attr["raw_value"] is not None else None})
        actual.append({"namespace_uri": node["name"]["namespace_uri"], "name": node["name"]["local_name"],
                       "parent": node["parent"], "attributes": attributes})
    require(len(expected) == len(actual), "AAPT/native node count differs")
    empty_raw_omissions = []
    for index, (a, b) in enumerate(zip(expected, actual)):
        for ordinal, (left, right) in enumerate(zip(a["attributes"], b["attributes"])):
            if left["raw"] is None and right["raw"] == "":
                # AAPT's text presentation does not print (Raw: ""). Keep
                # the exact native raw empty value and verify its index below.
                left["raw"] = ""
                empty_raw_omissions.append({"node": index, "attribute": ordinal})
        require(a == b, "AAPT/native tree differs at node %d\n%s\n%s" % (index, a, b))
    with zipfile.ZipFile(apk) as archive: raw = archive.read("AndroidManifest.xml")
    raw_indices = []
    at = 8
    while at < len(raw):
        kind, header, size = struct.unpack_from("<HHI", raw, at)
        require(size >= header and at + size <= len(raw), "public AXML chunk bounds")
        if kind == 0x102:
            attr_start, stride, count = struct.unpack_from("<HHH", raw, at + 24)
            raw_indices.append([struct.unpack_from("<I", raw, at + header + attr_start + i * stride + 8)[0] for i in range(count)])
        at += size
    require(len(raw_indices) == len(document["nodes"]), "raw independent node count")
    for node_index, node in enumerate(document["nodes"]):
        for attr_index, attr in enumerate(node["attributes"]):
            pool_index = raw_indices[node_index][attr_index]
            expected_raw = None if pool_index == 0xffffffff else document["strings"][pool_index]["value"]
            require(expected_raw == attr["raw_value"], "independent rawValue index differs")
    return {"nodes": len(actual), "attributes": sum(len(n["attributes"]) for n in actual), "complete_tree_equal": True,
            "comparison": "all document-order element namespace/name/parent and attribute namespace/name/resource_id/raw/rendered typed value",
            "aapt_empty_raw_presentation_omissions": empty_raw_omissions,
            "independent_raw_value_indices_verified": True}

def main():
    if sys.argv[1:] == ["final-checks"]:
        commands = [
            ("final/input-tests", ["cargo", "test", "-p", "mdd-input", "--locked", "--offline"]),
            ("final/input-clippy", ["cargo", "clippy", "-p", "mdd-input", "--all-targets", "--locked", "--offline", "--", "-D", "warnings"]),
            ("final/example-build", ["cargo", "build", "-p", "mdd-facts", "--example", "manifest_summary", "--locked", "--offline"]),
            ("final/python-check", [sys.executable, "-O", "tests/fixtures/manifest/check.py"]),
            ("final/a0-comparison", [sys.executable, "-O", "artifacts/mdd-025/manifest/compare_a0.py"]),
        ]
        for name, argv in commands:
            result = record(name, argv); require(result.returncode == 0, "final validation failed: " + name)
        print(json.dumps({"commands":len(commands), "all_exit_zero":True})); return
    if sys.argv[1:] == ["public"]:
        native = record("public-native", [NATIVE, PUBLIC, PUBLIC_SHA]); require(native.returncode == 0, "native public Manifest failed")
        aapt = record("public-aapt", [AAPT, "dump", "xmltree", "--file", "AndroidManifest.xml", PUBLIC]); require(aapt.returncode == 0, "AAPT public Manifest failed")
        result = compare_public(json.loads(native.stdout), aapt.stdout.decode("utf-8"))
        (OUT / "public-full-tree-comparison.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result)); return
    if sys.argv[1:] == ["small-aapt"]:
        results = []
        for name in ["utf8", "utf16", "aliased-pool", "styled-utf8", "styled-utf16", "unpaired-value-utf16", "long-utf8", "long-utf16", "ambiguous-prefix"]:
            apk = ROOT / ("tests/fixtures/manifest/generated/" + name + ".axml.apk")
            item = record("aapt-vectors/" + name, [AAPT, "dump", "xmltree", "--file", "AndroidManifest.xml", apk])
            require(item.returncode == 0, "AAPT vector rejected: " + name)
            native = record("native-vectors/" + name, [NATIVE, apk]); require(native.returncode == 0, "native vector rejected: " + name)
            comparison = compare_public(json.loads(native.stdout), item.stdout.decode("utf-8"), apk)
            results.append({"name": name, "exit_code": item.returncode, "complete_output_captured": True, **comparison})
        (OUT / "small-aapt-summary.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(results)); return
    raise RuntimeError("usage: run_validation.py public|small-aapt|final-checks")

if __name__ == "__main__": main()
