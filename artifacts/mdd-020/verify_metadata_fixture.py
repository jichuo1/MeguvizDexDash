#!/usr/bin/env python3
"""Independent scalar reference reader and handwritten expectation comparison."""
from __future__ import annotations

import json
import runpy
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    expected = json.loads((HERE / "expected.json").read_text())
    data = (HERE / "inputs/metadata-035.dex").read_bytes()
    reference = runpy.run_path(str(ROOT / "conformance/oracles/check_fixtures.py"))
    base = reference["dex"](data)
    require(base["strings_utf16"] == expected["strings_utf16"], "independent string units differ")
    strings = ["".join(map(chr, value)) for value in base["strings_utf16"]]
    fields = struct.unpack_from("<20I", data, 32)
    types = []
    for index in range(fields[8]):
        string_index = struct.unpack_from("<I", data, fields[9] + index * 4)[0]
        descriptor = strings[string_index]
        dimensions = len(descriptor) - len(descriptor.lstrip("["))
        types.append({"type_idx": index, "descriptor_string_idx": string_index, "descriptor": descriptor,
                      "shorty": "L" if dimensions or descriptor.startswith("L") else descriptor, "array_dimensions": dimensions})
    require(types == expected["types"], "independent type fields differ")
    prototypes = []
    for index in range(fields[10]):
        shorty, returned, parameter_offset = struct.unpack_from("<III", data, fields[11] + index * 12)
        if parameter_offset:
            count = struct.unpack_from("<I", data, parameter_offset)[0]
            parameters = list(struct.unpack_from("<" + "H" * count, data, parameter_offset + 4))
        else:
            parameters = []
        prototypes.append({"proto_idx": index, "shorty_string_idx": shorty, "shorty": strings[shorty],
            "return_type_idx": returned, "parameter_type_indices": parameters,
            "parameters_byte_offset": str(parameter_offset) if parameter_offset else None,
            "descriptor": "(" + "".join(types[parameter]["descriptor"] for parameter in parameters) + ")" + types[returned]["descriptor"]})
    require(prototypes == expected["prototypes"], "independent prototype fields differ")
    report = {"schema_version": "mdd.metadata-independent-oracle.v1", "success": True,
        "strings": len(strings), "types": types, "prototypes": prototypes,
        "provenance": "MDD-004 bounded Python header/string reader plus independently written scalar struct-based metadata reference. No production Rust parser or metadata generator imports.",
        "expectations": "artifacts/mdd-020/expected.json", "not_claimed": "complete DEX/ART verifier or DexSQL compatibility qualification"}
    (HERE / "independent-oracle.json").write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(f"independent metadata oracle passed: {len(strings)} strings, {len(types)} types, {len(prototypes)} prototypes")


if __name__ == "__main__":
    main()
