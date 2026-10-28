#!/usr/bin/env python3
"""Write tiny owned try/catch DEX fixtures; no production parser imports."""
import hashlib
import json
from pathlib import Path
import struct
import zlib

HERE = Path(__file__).resolve().parent


def leb(value):
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        result.append(byte | (128 if value else 0))
        if not value:
            return bytes(result)


def build(odd, invalid_handler=False):
    # All fixture strings are ASCII and sorted by DEX UTF-16 code units.
    strings = ["Lfixture/Try;", "Ljava/lang/Object;", "V", "run"]
    string_off = 112
    type_off = string_off + 4 * len(strings)
    proto_off = type_off + 4 * 3
    method_off = proto_off + 12
    class_off = method_off + 8
    data_off = class_off + 32
    data = bytearray(data_off)
    entries = [(0,1,0), (1,len(strings),string_off), (2,3,type_off), (3,1,proto_off),
               (5,1,method_off), (6,1,class_off), (0x2002,len(strings),len(data))]
    for index, text in enumerate(strings):
        raw = text.encode("ascii")
        struct.pack_into("<I", data, string_off + index * 4, len(data))
        data.extend(leb(len(raw)) + raw + b"\x00")
    for index, string_idx in enumerate([0,1,2]):
        struct.pack_into("<I", data, type_off + index * 4, string_idx)
    struct.pack_into("<III", data, proto_off, 2, 2, 0)
    struct.pack_into("<HHI", data, method_off, 0, 0, 3)
    data.extend(b"\x00" * (-len(data) % 4))
    code_off = len(data)
    entries.append((0x2001, 1, code_off))
    # const/4 v0,0; throw v0; move-exception v0; return-void; optional unreachable nop.
    words = [0x0012, 0x0027, 0x000d, 0x000e] + ([0x0000] if odd else [])
    data.extend(struct.pack("<HHHHII", 1, 0, 0, 1, 0, len(words)))
    data.extend(struct.pack("<" + "H" * len(words), *words))
    if len(words) % 2:
        data.extend(b"\x00\x00")
    tries_off = len(data)
    # One code-unit protected range at PC 1; handler_off 1 points after list size.
    data.extend(struct.pack("<IHH", 1, 1, 1))
    handlers_off = len(data)
    # One catch-all-only handler; target is PC 2 unless deliberately corrupted.
    data.extend(bytes([1, 0, 127 if invalid_handler else 2]))
    class_data_off = len(data)
    entries.append((0x2000, 1, class_data_off))
    data.extend(bytes([0,0,1,0]) + leb(0) + leb(9) + leb(code_off))
    struct.pack_into("<8I", data, class_off, 0, 1, 1, 0, 0xffffffff, 0, class_data_off, 0)
    data.extend(b"\x00" * (-len(data) % 4))
    map_off = len(data)
    entries.append((0x1000, 1, map_off))
    data.extend(struct.pack("<I", len(entries)))
    for kind, count, offset in entries:
        data.extend(struct.pack("<HHII", kind, 0, count, offset))
    struct.pack_into("<20I", data, 32, len(data), 112, 0x12345678, 0, 0, map_off,
                     len(strings), string_off, 3, type_off, 1, proto_off, 0, 0,
                     1, method_off, 1, class_off, len(data)-data_off, data_off)
    data[:8] = b"dex\n035\x00"
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data), {"code_off":code_off, "tries_off":tries_off, "handlers_off":handlers_off,
                         "insns_off":code_off+16, "insns_size_code_units":len(words),
                         "try_start_pc":1, "try_code_units":1, "handler_target_pc":127 if invalid_handler else 2,
                         "method_idx":0, "odd_padding":odd}


def main():
    output = HERE / "generated"
    output.mkdir(parents=True, exist_ok=True)
    records = []
    for name, odd, bad in [("owned-try-even.dex",False,False), ("owned-try-odd.dex",True,False),
                           ("owned-try-bad-handler.dex",True,True)]:
        raw, details = build(odd,bad)
        path = output / name
        if path.exists() and path.read_bytes() != raw:
            raise RuntimeError("refusing to overwrite different existing fixture: " + name)
        path.write_bytes(raw)
        records.append({"path":path.relative_to(HERE).as_posix(), "bytes":len(raw),
                        "sha256":hashlib.sha256(raw).hexdigest(), "expected":"invalid_handler" if bad else "valid_structural_fixture",
                        "hand_layout":details})
    manifest = {"schema_version":"mdd.owned-try-fixtures.v1", "files":records,
                "scope":"synthetic DEX; no device install or full ART verification"}
    target = HERE / "manifest.json"
    text = json.dumps(manifest,indent=2) + "\n"
    if target.exists() and target.read_text(encoding="utf-8") != text:
        raise RuntimeError("refusing to overwrite different existing fixture manifest")
    target.write_text(text,encoding="utf-8",newline="\n")
    print(json.dumps({"fixtures":len(records), "valid":2, "invalid_handler":1}))


if __name__ == "__main__":
    main()
