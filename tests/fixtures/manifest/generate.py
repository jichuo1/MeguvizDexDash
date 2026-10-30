"""Independent, deterministic resource-format vectors; no Rust parser imports."""
import hashlib
import json
import struct
from pathlib import Path
import zipfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
ANDROID = "http://schemas.android.com/apk/res/android"
N = 0xffffffff
P = lambda *x: struct.pack("<" + "I" * len(x), *x)
H = lambda *x: struct.pack("<" + "H" * len(x), *x)

def chunk(kind, header, payload):
    return H(kind, len(header) + 8) + P(len(header) + len(payload) + 8) + header + payload

def len8(n):
    return bytes([n]) if n < 128 else bytes([0x80 | (n >> 8), n & 255])

def pool(values, utf8=True, alias=False, styled=False):
    data, offsets = bytearray(), []
    for value in values:
        offsets.append(len(data))
        units = value.encode("utf-16-le", "surrogatepass")
        if utf8:
            raw = value.encode("utf-8")
            data += len8(len(units) // 2) + len8(len(raw)) + raw + b"\0"
        else:
            size = len(units) // 2
            data += (H(size) if size < 0x8000 else H(0x8000 | (size >> 16), size & 65535)) + units + b"\0\0"
    data += b"\0" * (-len(data) % 4)
    if alias:
        offsets[-1] = offsets[-2]
    style_offsets = [N] * len(values) if styled else []
    if styled:
        style_offsets[-1] = 0
    begin = 28 + 4 * (len(offsets) + len(style_offsets))
    style_data = P(0, 0, 0, N, N, N) if styled else b""
    return chunk(1, P(len(values), len(style_offsets), 0x100 if utf8 else 0, begin,
                       begin + len(data) if styled else 0),
                 P(*offsets) + P(*style_offsets) + data + style_data)

def node(kind, payload, line=1):
    return chunk(kind, P(line, N), payload)

def encode(utf8=True, *, typed=True, alias=False, styled=False, surrogate=False, long=False, all_types=False):
    strings = ["android", ANDROID, "manifest", "package", "versionCode", "versionName", "uses-sdk",
               "minSdkVersion", "targetSdkVersion", "uses-permission", "name", "permission", "application",
               "activity", "service", "receiver", "provider", "activity-alias", "exported", "permission",
               "example.test", "7.2", "p.permission", ".Main", ".Svc", ".Receiver", ".Provider", ".Alias",
               "label", "enabled", "ratio", "dimension", "fraction", "color", "nil", "empty", "hex", "text",
               "attrRef", "dynRef", "dynAttr", "unknownType", "trueNoncanon", "negativeInt", "", "same", "same"]
    if surrogate:
        strings[-1] = "\ud800"
    if long:
        strings[-1] = "long" * (100 if utf8 else 10000)
    sid = {value: i for i, value in enumerate(strings)}
    # Keep duplicate textual 'permission' values in the pool but bind element
    # and attribute explicitly. IDs are not inferred from parser output.
    records, expected = [], []
    def attr(ns, name, data_type, data, raw=None):
        return (sid[ns] if ns else N, sid[name], sid[raw] if raw is not None else N, data_type, data)
    def string_attr(ns, name, value):
        return attr(ns, name, 3, sid[value], value)
    def element(name, attributes, parent):
        ident = len(expected)
        expected.append({"name": name, "namespace_uri": None, "parent": parent,
                         "attributes": [{"namespace_uri": None if a[0] == N else strings[a[0]],
                                         "name": strings[a[1]], "raw": None if a[2] == N else strings[a[2]],
                                         "data_type": a[3], "data": strings[a[4]] if a[3] == 3 else a[4]}
                                        for a in attributes]})
        raw_attrs = b"".join(P(a[0], a[1], a[2]) + H(8) + bytes([0, a[3]]) + P(a[4]) for a in attributes)
        records.append(node(0x102, P(N, sid[name]) + H(20, 20, len(attributes), 0, 0, 0) + raw_attrs))
        return ident
    def end(name): records.append(node(0x103, P(N, sid[name])))
    records.append(node(0x100, P(sid["android"], sid[ANDROID])))
    element("manifest", [string_attr(None, "package", "example.test"), attr(ANDROID, "versionCode", 0x10, 7), string_attr(ANDROID, "versionName", "7.2")], None)
    element("uses-sdk", [attr(ANDROID, "minSdkVersion", 0x10, 21), attr(ANDROID, "targetSdkVersion", 0x10, 35)], 0); end("uses-sdk")
    for _ in range(2):
        element("uses-permission", [string_attr(ANDROID, "name", "p.permission")], 0); end("uses-permission")
    element("permission", [string_attr(ANDROID, "name", "p.permission")], 0); end("permission")
    app_attrs = []
    if typed:
        app_attrs = [attr(ANDROID, "label", 1, 0x7f010001), attr(ANDROID, "enabled", 0x12, 0),
                     attr(None, "ratio", 4, 0x7fc01234), attr(None, "dimension", 5, 0x100001),
                     attr(None, "fraction", 6, 0x200010), attr(None, "color", 0x1c, 0xff336699),
                     attr(None, "nil", 0, 0), attr(None, "empty", 0, 1), attr(None, "hex", 0x11, N)]
        if all_types:
            app_attrs += [attr(None, "attrRef", 2, 0x01010000), attr(None, "dynRef", 7, 0x02010001),
                          attr(None, "dynAttr", 8, 0x02010002), attr(None, "unknownType", 0x9f, 0xdeadbeef),
                          attr(None, "trueNoncanon", 0x12, 2), attr(None, "negativeInt", 0x10, N),
                          string_attr(None, "text", "")]
    app = element("application", app_attrs, 0)
    for name, value in [("activity", ".Main"), ("service", ".Svc"), ("receiver", ".Receiver"), ("provider", ".Provider"), ("activity-alias", ".Alias")]:
        attrs = [string_attr(ANDROID, "name", value)]
        if name == "service": attrs.append(attr(ANDROID, "exported", 0x12, N))
        element(name, attrs, app); end(name)
    records.append(node(0x104, P(sid["text"]) + H(8) + bytes([0, 3]) + P(sid["text"])))
    end("application"); end("manifest")
    records.append(node(0x101, P(sid["android"], sid[ANDROID])))
    resources = [0] * len(strings)
    for name, rid in [("name", 0x01010003), ("versionCode", 0x0101021b), ("versionName", 0x0101021c), ("exported", 0x01010010)]: resources[sid[name]] = rid
    data = pool(strings, utf8, alias, styled) + chunk(0x180, b"", P(*resources)) + b"".join(records)
    return H(3, 8) + P(len(data) + 8) + data, expected

def chunks(raw):
    at = 8
    while at < len(raw):
        kind, head, size = struct.unpack_from("<HHI", raw, at)
        yield kind, at, head, size
        at += size

def vectors():
    out = []
    def add(name, data, expected=None, code=None, note=""):
        out.append((name, data, {"expected_error": code, "tree": expected, "note": note}))
    for name, options in [("utf8", {}), ("utf16", {"utf8": False}), ("aliased-pool", {"alias": True}),
                          ("styled-utf8", {"styled": True}), ("styled-utf16", {"utf8": False, "styled": True}),
                          ("unpaired-value-utf16", {"utf8": False, "surrogate": True}),
                          ("long-utf8", {"long": True}), ("long-utf16", {"long": True, "utf8": False})]:
        data, tree = encode(**options); add(name + ".axml", data, tree)
    data, tree = encode(all_types=True); add("all-typed-values.axml", data, tree)
    base, tree = encode(); segments = list(chunks(base)); start = next(at for k, at, h, s in segments if k == 0x102)
    extra_ns = node(0x100, P(38, 1)); extra_end = node(0x101, P(38, 1))
    data = base[:start] + extra_ns + base[start:-24] + extra_end + base[-24:]
    data = data[:4] + P(len(data)) + data[8:]
    add("ambiguous-prefix.axml", data, tree, note="binary expanded name cannot prove which of two visible prefixes was originally used")
    def changed(name, at, replacement, code="INVALID_INPUT"):
        data = bytearray(base); data[at:at + len(replacement)] = replacement; add(name + ".axml", bytes(data), code=code)
    changed("bad-root-size", 4, P(len(base) - 4))
    changed("zero-chunk", 12, P(0))
    changed("bad-chunk-align", 12, P(29))
    changed("bad-header", 10, H(4))
    changed("huge-string-count", 16, P(N), "QUOTA_EXCEEDED")
    changed("bad-string-offset", 36, P(N))
    changed("bad-element-index", start + 20, P(N))
    changed("bad-namespace-index", start + 16, P(0))
    changed("bad-attribute-index", start + 40, P(N))
    changed("bad-typed-string-index", start + 52, P(N))
    changed("bad-value-size", start + 48, H(7))
    changed("bad-value-reserved", start + 50, b"\x01")
    changed("bad-attribute-stride", start + 26, H(16))
    changed("bad-attribute-count", start + 28, H(65535))
    changed("bad-special-index", start + 30, H(4))
    changed("duplicate-attribute", start + 56, base[start + 36:start + 56])
    end = next(at for k, at, h, s in segments if k == 0x103)
    child_start = [at for k, at, h, s in segments if k == 0x102][1]
    child_end = end + 24
    shadow = node(0x100, P(0, 20)); shadow_end = node(0x101, P(0, 20))
    data = base[:child_start] + shadow + base[child_start:child_end] + shadow_end + base[child_end:]
    data = data[:4] + P(len(data)) + data[8:]; add("shadowed-uri.axml", data, code="INVALID_INPUT")
    changed("mismatched-end", end + 20, P(2))
    ns_end = segments[-1][1]
    data = base[:ns_end]; data = data[:4] + P(len(data)) + data[8:]; add("missing-namespace-end.axml", data, code="INVALID_INPUT")
    data = base[:start] + base[start + segments[[k for k, *_ in segments].index(0x102)][3]:]
    data = data[:4] + P(len(data)) + data[8:]; add("missing-root-start.axml", data, code="INVALID_INPUT")
    changed("unknown-chunk", segments[-2][1], H(0x199), "UNSUPPORTED_CAPABILITY")
    strings_start = struct.unpack_from("<I", base, 28)[0] + 8
    changed("bad-resource-utf8", strings_start + 2, b"\xff")
    changed("bad-utf8-unit-length", strings_start, b"\x01")
    changed("bad-utf8-terminator", strings_start + 2 + len("android"), b"\x01")
    changed("bad-overlong-resource-utf8", strings_start + 2, b"\xc0\x80")
    map_kind, map_at, map_header, map_size = next(item for item in segments if item[0] == 0x180)
    data = bytearray(base[:map_at + map_size] + P(1) + base[map_at + map_size:])
    struct.pack_into("<I", data, 4, len(data)); struct.pack_into("<I", data, map_at + 4, map_size + 4)
    add("bad-resource-map-count.axml", bytes(data), code="INVALID_INPUT")
    data_styled, _ = encode(styled=True)
    style_start = 8 + struct.unpack_from("<I", data_styled, 32)[0]
    data = bytearray(data_styled); struct.pack_into("<I", data, style_start, N - 1)
    add("bad-style-name.axml", bytes(data), code="INVALID_INPUT")
    data = bytearray(data_styled); struct.pack_into("<I", data, style_start + 8, 40)
    add("bad-style-character-range.axml", bytes(data), code="INVALID_INPUT")
    count = struct.unpack_from("<I", data_styled, 16)[0]
    data = bytearray(data_styled); struct.pack_into("<I", data, 36 + count * 4 + (count - 1) * 4, N - 1)
    add("bad-style-offset.axml", bytes(data), code="INVALID_INPUT")
    data = bytearray(data_styled); struct.pack_into("<I", data, 20, count + 1)
    add("bad-style-count.axml", bytes(data), code="INVALID_INPUT")
    data16, _ = encode(utf8=False)
    data = bytearray(data16); pool_start = struct.unpack_from("<I", data, 28)[0] + 8
    data[pool_start + 2 + 2 * len("android"):pool_start + 4 + 2 * len("android")] = H(1)
    add("bad-utf16-terminator.axml", bytes(data), code="INVALID_INPUT")
    data = bytearray(data16); manifest_string = pool_start + struct.unpack_from("<I", data, 36 + 2 * 4)[0]
    struct.pack_into("<H", data, manifest_string + 2, 0xd800)
    add("bad-unpaired-structural-name.axml", bytes(data), code="INVALID_INPUT")
    for size in [1, 7, 9, len(base) - 1]: add("truncated-" + str(size) + ".axml", base[:size], code="INVALID_INPUT")
    xml = ('<?xml version="1.0" encoding="UTF-8"?><manifest xmlns:a="' + ANDROID + '" package="example.test" a:versionCode="7" a:versionName="7.2">'
           '<uses-sdk a:minSdkVersion="21" a:targetSdkVersion="35"/><uses-permission a:name="p.permission"/>'
           '<uses-permission a:name="p.permission"/><application><activity a:name=".Main"/><service a:name=".Svc" a:exported="false"/></application></manifest>').encode()
    add("text-basic.xml", xml, note="XML strings are not inferred compiled integers/booleans")
    add("text-bom.xml", b"\xef\xbb\xbf" + xml)
    add("text-entities.xml", b'<manifest package="a&amp;b&#x1f600;"><application label="x&#xA;y&#9;z\tq"/>a&amp;<![CDATA[<b>]]></manifest>')
    add("text-ns-shadow.xml", b'<manifest xmlns:a="urn:a"><a:n xmlns:a="urn:b" a:v="x"/><a:n/><n xmlns="urn:default" plain="ok"/></manifest>')
    for name, raw in {
        "dtd": b'<!DOCTYPE manifest [<!ENTITY x "x">]><manifest/>',
        "external-dtd": b'<!DOCTYPE manifest SYSTEM "file:///not-read"><manifest/>',
        "entity": b'<manifest>&custom;</manifest>',
        "bad-ref": b'<manifest x="&#0;"/>', "control-ref": b'<manifest>&#1;</manifest>',
        "utf8": b'<manifest x="\xff"/>', "utf16-xml": b'\xff\xfe<\x00m\x00',
        "prefix": b'<manifest a:x="y"/>', "duplicate-expanded": b'<manifest xmlns:a="urn:x" xmlns:b="urn:x" a:x="1" b:x="2"/>',
        "duplicate": b'<manifest x="1" x="2"/>', "close": b'<manifest><a></manifest>',
        "truncated": b'<manifest>', "two-roots": b'<manifest/><manifest/>',
        "root": b'<application/>', "colon-name": b'<manifest><a:b:c/></manifest>',
        "numeric-name": b'<manifest><1bad/></manifest>', "bad-binding": b'<manifest xmlns:xml="urn:x"/>',
        "empty-prefix-uri": b'<manifest xmlns:a=""/>', "encoding": b'<?xml version="1.0" encoding="UTF-16"?><manifest/>',
        "decl-order": b'<?xml version="1.0" standalone="yes" encoding="UTF-8"?><manifest/>',
        "late-decl": b'<!--x--><?xml version="1.0"?><manifest/>', "outside": b'<manifest/>x',
        "cdata-outside": b'<![CDATA[x]]><manifest/>', "literal-control": b'<manifest>\x01</manifest>',
        "bad-comment": b'<manifest><!--a--b--></manifest>',
        "literal-less-than": b'<manifest x="a<b"/>',
    }.items(): add("bad-text-" + name + ".xml", raw, code="INVALID_INPUT")
    return out

def main():
    folder = ROOT / "generated"; folder.mkdir(parents=True, exist_ok=True)
    manifest = []
    for name, raw, expected in vectors():
        (folder / name).write_bytes(raw)
        if expected["expected_error"] is None:
            target = folder / (name + ".apk")
            with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
                info = zipfile.ZipInfo("AndroidManifest.xml", (1980, 1, 1, 0, 0, 0)); info.create_system = 0
                archive.writestr(info, raw)
        if expected["expected_error"] is None and name.endswith(".xml"):
            tree = []
            def expanded(name):
                if name.startswith("{"):
                    ns, local = name[1:].split("}", 1); return ns, local
                return None, name
            def visit(element, parent):
                ident = len(tree); ns, name = expanded(element.tag)
                attrs = []
                for key, value in element.attrib.items():
                    ans, aname = expanded(key); attrs.append({"namespace_uri": ans, "name": aname, "text": value})
                tree.append({"namespace_uri": ns, "name": name, "parent": parent, "attributes": attrs})
                for child in element: visit(child, ident)
            visit(ET.fromstring(raw), None); expected["tree"] = tree
        manifest.append({"file": "generated/" + name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), **expected})
    (ROOT / "manifest.json").write_text(json.dumps({"schema_version": "mdd.manifest-vectors.v1", "cases": manifest}, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({"cases": len(manifest), "positive": sum(x["expected_error"] is None for x in manifest), "negative": sum(x["expected_error"] is not None for x in manifest)}))

if __name__ == "__main__": main()
