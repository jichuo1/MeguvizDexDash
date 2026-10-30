"""Small real ZIP64 fixtures, plus explicitly invalid declaration/budget vectors."""
from pathlib import Path
import hashlib
import io
import json
import struct
import warnings
import zipfile
import zlib

HERE = Path(__file__).resolve().parent
DEX = (HERE.parent / 'generated/minimal-035.dex').read_bytes()
OTHER = (HERE.parent / 'generated/structured-035.dex').read_bytes()


def extra(payload):
    return struct.pack('<HH', 1, len(payload)) + payload


def make(entries, *, method=0, mode='all', local64=True, descriptor=None, global64=True, duplicate_central=False, duplicate_local=False, extension=b'', local_padding=b'', descriptor_wide=None):
    data = bytearray(); records = []; layout = []
    for name, raw in entries:
        name = name.encode('ascii'); offset = len(data)
        if method == 8:
            compressor = zlib.compressobj(wbits=-15); compressed = compressor.compress(raw) + compressor.flush()
        else:
            compressed = raw
        crc = zlib.crc32(raw); flags = 8 if descriptor else 0; needed = 45 if local64 or mode != 'plain' else 20
        local_extra = extra(struct.pack('<QQ', 0 if descriptor else len(raw), 0 if descriptor else len(compressed))) if local64 else b''
        if duplicate_local:
            local_extra += local_extra
        local_extra += local_padding
        comp32 = 0xffffffff if local64 else 0 if descriptor else len(compressed)
        size32 = 0xffffffff if local64 else 0 if descriptor else len(raw)
        data.extend(struct.pack('<4s5H3I2H', b'PK\x03\x04', needed, flags, method, 0, 33, 0 if descriptor else crc, comp32, size32, len(name), len(local_extra)))
        data.extend(name + local_extra); data_start = len(data); data.extend(compressed); descriptor_start = len(data)
        if descriptor:
            if descriptor == 'signed':
                data.extend(b'PK\x07\x08')
            wide = local64 or mode != 'plain' if descriptor_wide is None else descriptor_wide
            data.extend(struct.pack('<IQQ' if wide else '<III', crc, len(compressed), len(raw)))
        values = []; csize = len(compressed); usize = len(raw); local_offset = offset; disk = 0
        if mode in ['all', 'size']:
            usize = 0xffffffff; values.append(struct.pack('<Q', len(raw)))
        if mode in ['all', 'compressed']:
            csize = 0xffffffff; values.append(struct.pack('<Q', len(compressed)))
        if mode in ['all', 'offset']:
            local_offset = 0xffffffff; values.append(struct.pack('<Q', offset))
        if mode == 'disk':
            disk = 0xffff; values.append(struct.pack('<I', 0))
        central_extra = extra(b''.join(values)) if values else b''
        if duplicate_central:
            central_extra += central_extra
        records.append(struct.pack('<4s6H3I5H2I', b'PK\x01\x02', 45, needed, flags, method, 0, 33, crc, csize, usize, len(name), len(central_extra), 0, disk, 0, 0, local_offset) + name + central_extra)
        layout.append({'local': offset, 'local_extra': offset + 30 + len(name), 'data_start': data_start, 'descriptor_start': descriptor_start,
                       'name': name.decode(), 'size': len(raw), 'compressed': len(compressed), 'crc32': crc})
    central_start = len(data)
    for row, metadata in zip(records, layout):
        metadata['central'] = len(data); metadata['central_extra'] = len(data) + 46 + len(metadata['name']); data.extend(row)
    central_size = len(data) - central_start
    zip64_start = len(data)
    if global64:
        data.extend(struct.pack('<4sQ2H2I4Q', b'PK\x06\x06', 44 + len(extension), 45, 45, 0, 0, len(entries), len(entries), central_size, central_start) + extension)
        locator = len(data); data.extend(struct.pack('<4sIQI', b'PK\x06\x07', 0, zip64_start, 1))
    else:
        locator = None
    end = len(data)
    data.extend(struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 0xffff if global64 else len(entries), 0xffff if global64 else len(entries), 0xffffffff if global64 else central_size, 0xffffffff if global64 else central_start, 0))
    return bytes(data), {'members': layout, 'central_start': central_start, 'central_size': central_size, 'zip64_start': zip64_start if global64 else None, 'locator': locator, 'end': end}


def python_forced(method, stream=False):
    class NonSeekable(io.BytesIO):
        def seekable(self):
            return False
        def seek(self, *args):
            raise io.UnsupportedOperation('streaming fixture')
    target = NonSeekable() if stream else io.BytesIO()
    with zipfile.ZipFile(target, 'w', allowZip64=True) as writer:
        info = zipfile.ZipInfo('classes.dex', (1980, 1, 1, 0, 0, 0)); info.compress_type = method; info.create_system = 0
        with writer.open(info, 'w', force_zip64=True) as member:
            member.write(DEX)
    return target.getvalue()


def many_members(count):
    target = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(target, 'w', allowZip64=True) as writer:
        warnings.simplefilter('ignore', UserWarning)
        for ordinal in range(count):
            info = zipfile.ZipInfo('classes.dex' if ordinal == 0 else 'r', (1980, 1, 1, 0, 0, 0)); info.create_system = 0
            writer.writestr(info, DEX if ordinal == 0 else b'')
    return target.getvalue()


def fixtures():
    entries = [('classes.dex', DEX), ('assets/raw.bin', b'\0\xffresource')]
    cases = {}
    def add(name, data, expected='ok', layout=None, note=None):
        cases[name] = (data, {'expected': expected, 'layout': layout, 'note': note})
    for method, label in [(0, 'stored'), (8, 'deflated')]:
        data, layout = make(entries, method=method); add('full-' + label, data, layout=layout)
        for descriptor in ['signed', 'unsigned']:
            data, layout = make(entries, method=method, descriptor=descriptor); add('descriptor-' + label + '-' + descriptor, data, layout=layout)
        add('python-force-local-' + label, python_forced(method), note='Python stdlib force_zip64=True, normal central/EOCD fields')
        add('python-stream-local-' + label, python_forced(method, True), note='Python nonseekable force_zip64, zero local ZIP64 placeholders and 64-bit descriptor')
    for mode in ['size', 'compressed', 'offset', 'disk']:
        data, layout = make(entries, method=8, mode=mode, local64=False); add('conditional-' + mode, data, layout=layout)
    data, layout = make([('classes.dex', DEX), ('classes.dex', OTHER)], method=8); add('duplicate-name', data, layout=layout)
    data, layout = make([('classes.dex', DEX), ('classes2.dex', DEX)]); add('duplicate-content', data, layout=layout)
    data, layout = make([]); add('empty', data, layout=layout)
    data, layout = make(entries, extension=struct.pack('<HI', 0x1234, 3) + b'abc'); add('end-extension', data, layout=layout)
    data, layout = make(entries, mode='plain', local64=False, global64=False); add('plain32', data, layout=layout)
    for length in [1, 2, 3]:
        data, layout = make(entries, mode='plain', local64=False, global64=False, local_padding=b'\0' * length); add('plain32-local-padding-' + str(length), data, layout=layout)
    data, layout = make(entries, mode='plain', local64=False, global64=False, local_padding=b'\x01'); add('plain32-local-nonzero-truncated-extra', data, 'INVALID_INPUT', layout)
    data, layout = make(entries, mode='plain', local64=False, descriptor='signed', global64=True); add('count-only-zip64-with-32-descriptor', data, layout=layout)
    data, layout = make(entries, method=8, mode='offset', local64=False, descriptor='unsigned'); changed=bytearray(data)
    for member in layout['members']:struct.pack_into('<H', changed, member['local']+4, 20)
    add('central-offset64-local-version20-descriptor64', bytes(changed), layout=layout)
    for name, options in [('duplicate-central-extra', {'duplicate_central': True}), ('duplicate-local-extra', {'duplicate_local': True})]:
        data, layout = make(entries, **options); add(name, data, 'INVALID_INPUT', layout)
    base, layout = make(entries, method=8)
    mutations = {
        'bad-locator-offset': ('Q', layout['locator'] + 8, len(base) + 100, 'INVALID_INPUT'),
        'bad-record-size': ('Q', layout['zip64_start'] + 4, 43, 'INVALID_INPUT'),
        'declared-record-huge': ('Q', layout['zip64_start'] + 4, 1 << 63, 'QUOTA_EXCEEDED'),
        'bad-disk-count': ('Q', layout['zip64_start'] + 24, 3, 'INVALID_INPUT'),
        'declared-directory-huge': ('Q', layout['zip64_start'] + 40, 1 << 63, 'QUOTA_EXCEEDED'),
        'declared-offset-overflow': ('Q', layout['zip64_start'] + 48, (1 << 64) - 1, 'INVALID_INPUT'),
        'multi-volume': ('I', layout['locator'] + 16, 2, 'UNSUPPORTED_CAPABILITY'),
        'zero-disks': ('I', layout['locator'] + 16, 0, 'INVALID_INPUT'),
        'bad-extra-length': ('H', layout['members'][0]['central_extra'] + 2, 8, 'INVALID_INPUT'),
        'bad-local-zip64-version': ('H', layout['members'][0]['local'] + 4, 20, 'INVALID_INPUT'),
        'bad-central-zip64-version': ('H', layout['members'][0]['central'] + 6, 20, 'INVALID_INPUT'),
        'local-size-mismatch': ('Q', layout['members'][0]['local_extra'] + 4, len(DEX) + 1, 'INVALID_INPUT'),
        'local-offset-u64-overflow': ('Q', layout['members'][0]['central_extra'] + 20, (1 << 64) - 1, 'INVALID_INPUT'),
        'central-local-name-mismatch': ('B', layout['members'][0]['local'] + 30, ord('x'), 'INVALID_INPUT'),
    }
    for name, (kind, at, value, expected) in mutations.items():
        changed = bytearray(base); struct.pack_into('<' + kind, changed, at, value); add(name, bytes(changed), expected, layout)
    changed = bytearray(base); struct.pack_into('<QQ', changed, layout['zip64_start'] + 24, (1 << 64) - 1, (1 << 64) - 1); add('declared-count-huge', bytes(changed), 'QUOTA_EXCEEDED', layout)
    changed = bytearray(base); changed[layout['locator']:layout['locator'] + 4] = b'BAD!'; add('missing-locator-signature', bytes(changed), 'INVALID_INPUT', layout)
    changed = bytearray(base); at = layout['members'][0]['central_extra'] + 4; original, compressed = struct.unpack_from('<QQ', changed, at); struct.pack_into('<QQ', changed, at, compressed, original); add('wrong-extra-order', bytes(changed), 'INVALID_INPUT', layout)
    changed = bytearray(base)
    for m in layout['members']:
        struct.pack_into('<Q', changed, m['central_extra'] + 4, (1 << 63)); struct.pack_into('<Q', changed, m['local_extra'] + 4, (1 << 63))
    add('declared-total-overflow', bytes(changed), 'QUOTA_EXCEEDED', layout, 'Declaration-only invalid/over-budget vector, not a legal huge archive; test with per-member/total limits u64::MAX')
    changed = bytearray(base); struct.pack_into('<Q', changed, layout['members'][0]['central_extra'] + 4, (1 << 64) - 1); add('declared-member-huge', bytes(changed), 'QUOTA_EXCEEDED', layout, 'Declaration-only quota vector; no true 4GB data allocated')
    changed = bytearray(base); changed[layout['members'][0]['data_start']] ^= 1; add('bad-selected-payload', bytes(changed), 'INVALID_INPUT', layout, 'Selected member must be fully decompressed and CRC checked')
    data, d = make(entries, method=8, descriptor='signed'); changed = bytearray(data); changed[d['members'][0]['descriptor_start'] + 4] ^= 1; add('bad-descriptor-crc', bytes(changed), 'INVALID_INPUT', d)
    data, d = make(entries, method=8, descriptor='unsigned'); changed = bytearray(data); struct.pack_into('<Q', changed, d['members'][0]['descriptor_start'] + 4, d['members'][0]['compressed'] + 1); add('bad-descriptor-size', bytes(changed), 'INVALID_INPUT', d)
    data, d = make(entries, method=8, descriptor='signed', descriptor_wide=False); add('bad-descriptor-width', data, 'INVALID_INPUT', d)
    for count in [65535, 65536]:
        add('count-' + str(count), many_members(count), note='Real small archive with many zero-byte duplicate resource names; not 4GB payload')
        cases['count-' + str(count)][1]['expected_count'] = count
        cases['count-' + str(count)][1]['large_metadata'] = True
    return cases


def main():
    generated = HERE / 'generated'; generated.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, (data, metadata) in fixtures().items():
        path = generated / (name + '.zip'); path.write_bytes(data)
        rows.append({'id': name, 'path': path.relative_to(HERE).as_posix(), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), **metadata})
    payload = {'schema_version': 'mdd.zip64-fixtures.v1', 'specification': 'PKWARE APPNOTE 6.3.10 sections 4.3.9,4.3.14-16,4.5.3',
               'source_url': 'https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT', 'generator': 'tests/fixtures/zip64/generate.py',
               'large_data_allocated': False, 'files': rows}
    (HERE / 'manifest.json').write_bytes((json.dumps(payload, indent=2) + '\n').encode())
    print(json.dumps({'fixtures': len(rows), 'positive': sum(r['expected'] == 'ok' for r in rows)}))


if __name__ == '__main__':
    main()
