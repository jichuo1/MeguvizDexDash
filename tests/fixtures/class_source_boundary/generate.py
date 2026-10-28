#!/usr/bin/env python3
"""Build independent tiny DEX fixtures for class source/null identity boundaries."""
import hashlib
import json
from pathlib import Path
import struct
import zlib

HERE = Path(__file__).resolve().parent


def encoded(units):
    value = bytearray([len(units)])
    for unit in units:
        if 0 < unit < 128:
            value.append(unit)
        elif unit < 2048:
            value.extend([0xc0 | (unit >> 6), 0x80 | (unit & 63)])
        else:
            value.extend([0xe0 | (unit >> 12), 0x80 | ((unit >> 6) & 63), 0x80 | (unit & 63)])
    return bytes(value) + b"\0"


def build(case):
    choices = {"null-source":(0,1,0xffffffff), "empty-source":(0,1,0),
               "surrogate-source":(0,1,3), "root-empty-source":(1,0xffffffff,0),
               "bad-source-index":(0,1,4)}
    if case not in choices:
        raise ValueError("unknown fixture case")
    class_idx, superclass_idx, source_idx = choices[case]
    texts = [[], list(b"Lfixture/Empty;"), list(b"Ljava/lang/Object;"), [0xd800]]
    string_off = 112
    type_off = string_off + len(texts) * 4
    class_off = type_off + 2 * 4
    data_off = class_off + 32
    data = bytearray(data_off)
    entries = [(0,1,0), (1,4,string_off), (2,2,type_off), (6,1,class_off), (0x2002,4,data_off)]
    for index, units in enumerate(texts):
        struct.pack_into("<I", data, string_off + index * 4, len(data))
        data.extend(encoded(units))
    struct.pack_into("<II", data, type_off, 1, 2)
    struct.pack_into("<8I", data, class_off, class_idx, 1, superclass_idx, 0, source_idx, 0, 0, 0)
    data.extend(b"\0" * (-len(data) % 4))
    map_off = len(data)
    entries.append((0x1000,1,map_off))
    data.extend(struct.pack("<I", len(entries)))
    for kind, count, offset in entries:
        data.extend(struct.pack("<HHII", kind, 0, count, offset))
    struct.pack_into("<20I", data, 32, len(data), 112, 0x12345678, 0, 0, map_off,
                     4, string_off, 2, type_off, 0, 0, 0, 0, 0, 0, 1, class_off,
                     len(data)-data_off, data_off)
    data[:8] = b"dex\n035\0"
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data), {"class_idx":class_idx,"superclass_idx":superclass_idx,
                         "source_file_idx":source_idx,"string_count":len(texts)}


def main():
    output = HERE / "generated"
    output.mkdir(parents=True,exist_ok=True)
    records = []
    for case in ["null-source", "empty-source", "surrogate-source", "root-empty-source", "bad-source-index"]:
        raw, layout = build(case)
        path = output / (case + ".dex")
        if path.exists() and path.read_bytes() != raw:
            raise RuntimeError("refusing to overwrite different existing fixture")
        path.write_bytes(raw)
        records.append({"id":case,"path":path.relative_to(HERE).as_posix(),"bytes":len(raw),
                        "sha256":hashlib.sha256(raw).hexdigest(),"hand_layout":layout,
                        "expectation":"invalid_source_index" if case == "bad-source-index" else "valid_structural_fixture"})
    manifest = {"schema_version":"mdd.class-source-boundaries.v1", "files":records,
                "scope":"synthetic DEX; no device installation or full ART verification"}
    target = HERE / "manifest.json"
    content = json.dumps(manifest,indent=2)+"\n"
    if target.exists() and target.read_text(encoding="utf-8") != content:
        raise RuntimeError("refusing to overwrite different fixture manifest")
    target.write_text(content,encoding="utf-8",newline="\n")
    print(json.dumps({"fixtures":len(records),"valid":4,"invalid_source_index":1}))


if __name__ == "__main__":
    main()
