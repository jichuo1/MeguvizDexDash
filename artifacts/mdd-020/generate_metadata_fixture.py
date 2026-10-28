#!/usr/bin/env python3
"""Independent standard-library writer of a controlled metadata-only DEX."""
from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "inputs"


def seal(data):
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data)


def build():
    # Offsets and manual expected values are reviewed separately in expected.json.
    strings = [b"I", b"J", b"Ljava/lang/String;", b"V", b"VIJLL", b"VJI", b"[I"]
    data = bytearray(196)
    string_offsets = []
    for index, value in enumerate(strings):
        string_offsets.append(len(data))
        struct.pack_into("<I", data, 112 + 4 * index, len(data))
        data.extend(bytes([len(value)]) + value + b"\0")
    for index, string_index in enumerate([0, 1, 2, 3, 6]):
        struct.pack_into("<I", data, 140 + index * 4, string_index)
    while len(data) % 4:
        data.append(0)
    first_parameters = len(data)
    data.extend(struct.pack("<I4H", 4, 0, 1, 2, 4))
    second_parameters = len(data)
    data.extend(struct.pack("<I2H", 2, 1, 0))
    struct.pack_into("<9I", data, 160, 3, 3, 0, 4, 3, first_parameters, 5, 3, second_parameters)
    map_off = len(data)
    entries = [(0, 1, 0), (1, 7, 112), (2, 5, 140), (3, 3, 160), (0x2002, 7, 196),
               (0x1001, 2, first_parameters), (0x1000, 1, map_off)]
    data.extend(struct.pack("<I", len(entries)))
    for kind, count, offset in entries:
        data.extend(struct.pack("<HHII", kind, 0, count, offset))
    data[:8] = b"dex\n035\0"
    struct.pack_into("<20I", data, 32, len(data), 112, 0x12345678, 0, 0, map_off,
                     7, 112, 5, 140, 3, 160, 0, 0, 0, 0, 0, 0, len(data) - 196, 196)
    return seal(data), string_offsets, first_parameters


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    positive, string_offsets, params = build()
    cases = [("metadata-035.dex", positive, "valid", None)]

    def mutation(name, offset, value, width, reason):
        data = bytearray(positive)
        data[offset:offset + width] = value.to_bytes(width, "little")
        cases.append((name, seal(data), "invalid", reason))

    mutation("bad-shorty.dex", 172, 5, 4, "SHORTY_DESCRIPTOR_MISMATCH")
    mutation("bad-return-index.dex", 176, 5, 4, "INDEX_OUT_OF_RANGE")
    mutation("bad-parameter-index.dex", params + 4, 0xffff, 2, "INDEX_OUT_OF_RANGE")
    mutation("bad-void-parameter.dex", params + 4, 3, 2, "VOID_PARAMETER")
    mutation("bad-utf16-length.dex", string_offsets[0], 2, 1, "STRING_LENGTH_MISMATCH")
    mutation("bad-mutf8-leading.dex", string_offsets[0] + 1, 0x80, 1, "INVALID_MUTF8")
    mutation("bad-type-descriptor.dex", 140, 4, 4, "INVALID_TYPE_DESCRIPTOR")
    data = bytearray(positive)
    data[140:148] = struct.pack("<II", 1, 0)
    cases.append(("bad-type-order.dex", seal(data), "invalid", "TYPE_IDS_NOT_STRICT_ORDER"))
    data = bytearray(positive)
    data[172:184], data[184:196] = data[184:196], data[172:184]
    cases.append(("bad-prototype-order.dex", seal(data), "invalid", "PROTO_IDS_NOT_STRICT_ORDER"))
    manifest = []
    for name, value, outcome, reason in cases:
        (OUT / name).write_bytes(value)
        manifest.append({"path": "artifacts/mdd-020/inputs/" + name, "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest(), "expected": outcome, "reason": reason})
    (HERE / "input-manifest.json").write_text(json.dumps({"schema_version": "mdd.metadata-fixtures.v1", "generator": "artifacts/mdd-020/generate_metadata_fixture.py",
        "claim": "controlled metadata-only DEX and invalid mutants, not installable application or complete ART verifier qualification",
        "files": manifest}, indent=2) + "\n", encoding="utf-8")
    print(f"generated {len(manifest)} metadata fixtures")


if __name__ == "__main__":
    main()
