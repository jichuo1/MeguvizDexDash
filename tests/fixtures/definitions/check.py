"""Independent, small definition oracle. Does not import generator or Rust code."""
from pathlib import Path
import hashlib
import json
import struct
import zlib

HERE = Path(__file__).resolve().parent


class Invalid(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def decode(data):
    require(data[:4] == b'dex\n', 'MAGIC')
    require(hashlib.sha1(data[32:]).digest() == data[12:32], 'SHA1')
    require(zlib.adler32(data[12:]) == struct.unpack_from('<I', data, 8)[0], 'ADLER32')
    header = struct.unpack_from('<20I', data, 32)
    def word(at):
        require(0 <= at <= len(data) - 4, 'RANGE')
        return struct.unpack_from('<I', data, at)[0]
    def leb(at):
        value = 0
        for shift in range(0, 35, 7):
            require(at < len(data), 'TRUNCATED')
            part = data[at]; at += 1; value |= (part & 127) << shift
            if not part & 128:
                require(value <= 0xffffffff, 'LEB_OVERFLOW')
                return value, at
        raise Invalid('LEB_OVERFLOW')
    strings = []
    for ordinal in range(header[6]):
        at = word(header[7] + ordinal * 4); size, at = leb(at)
        end = data.index(0, at)
        text = data[at:end].decode('utf-8', 'surrogatepass')
        require(len(text.encode('utf-16-le', 'surrogatepass')) // 2 == size, 'STRING_LENGTH')
        strings.append(text)
    types = [strings[word(header[9] + ordinal * 4)] for ordinal in range(header[8])]
    prototypes = []
    for ordinal in range(header[10]):
        shorty, result, parameters = struct.unpack_from('<3I', data, header[11] + ordinal * 12)
        args = [types[struct.unpack_from('<H', data, parameters + 4 + i * 2)[0]] for i in range(word(parameters))] if parameters else []
        prototypes.append('(' + ''.join(args) + ')' + types[result])
    fields = []
    for ordinal in range(header[12]):
        owner, typ, name = struct.unpack_from('<HHI', data, header[13] + ordinal * 8)
        require(not any(0xd800 <= ord(c) <= 0xdfff for c in strings[name]), 'NON_SCALAR_MEMBER_NAME')
        fields.append((owner, types[owner] + '->' + strings[name] + ':' + types[typ]))
    methods = []
    for ordinal in range(header[14]):
        owner, proto, name = struct.unpack_from('<HHI', data, header[15] + ordinal * 8)
        methods.append((owner, types[owner] + '->' + strings[name] + prototypes[proto]))
    classes = [struct.unpack_from('<8I', data, header[17] + ordinal * 32) for ordinal in range(header[16])]
    positions = {}
    for ordinal, cls in enumerate(classes):
        require(cls[0] not in positions, 'DUPLICATE_CLASS_DEFINITION')
        positions[cls[0]] = ordinal
    maps = [struct.unpack_from('<HHII', data, header[5] + 4 + i * 12) for i in range(word(header[5]))]
    type_list_map = next(row for row in maps if row[0] == 0x1001)
    type_list_starts = set(); at = type_list_map[3]
    for _ in range(type_list_map[2]):
        at = (at + 3) & ~3; type_list_starts.add(at); at += 4 + word(at) * 2
    map_index = next(i for i, row in enumerate(maps) if row[0] == 0x2000)
    class_data_count = maps[map_index][2]; class_data_end = maps[map_index + 1][3] if map_index + 1 < len(maps) else len(data)
    at = maps[map_index][3]; class_data_starts = set()
    for _ in range(class_data_count):
        class_data_starts.add(at); counts = []
        for _ in range(4):
            value, at = leb(at); counts.append(value)
        owner = None; seen_fields = set(); seen_methods = set()
        for group, size in enumerate(counts):
            require(at + size * (2 if group < 2 else 3) <= class_data_end, 'TRUNCATED_CLASS_DATA_LAYOUT')
            previous = 0
            for ordinal in range(size):
                delta, at = leb(at); flags, at = leb(at)
                field = group < 2
                require(ordinal == 0 or delta != 0, 'DUPLICATE_FIELD_INDEX' if field else 'DUPLICATE_METHOD_INDEX')
                require(previous + delta <= 0xffffffff, 'FIELD_DELTA_OVERFLOW' if field else 'METHOD_DELTA_OVERFLOW')
                index = previous + delta; previous = index
                refs = fields if field else methods
                require(index < len(refs), 'FIELD_INDEX_OUT_OF_RANGE' if field else 'METHOD_INDEX_OUT_OF_RANGE')
                seen = seen_fields if field else seen_methods
                require(index not in seen, 'DUPLICATE_FIELD_DEFINITION' if field else 'DUPLICATE_METHOD_DEFINITION'); seen.add(index)
                require(owner is None or owner == refs[index][0], 'FIELD_OWNER_MISMATCH' if field else 'METHOD_OWNER_MISMATCH')
                if field:
                    require(bool(flags & 8) == (group == 0), 'FIELD_KIND_FLAGS_MISMATCH')
                else:
                    code, at = leb(at)
                    require(bool(flags & (8 | 2 | 0x10000)) == (group == 2), 'METHOD_KIND_FLAGS_MISMATCH')
                    require(not (flags & (0x100 | 0x400)) or code == 0, 'NATIVE_OR_ABSTRACT_HAS_CODE')
                    require(bool(flags & (0x100 | 0x400)) or code != 0, 'CONCRETE_METHOD_MISSING_CODE')
                owner = refs[index][0]
                require(at <= class_data_end, 'TRUNCATED_CLASS_DATA_LAYOUT')
        require(owner is None or owner in positions, 'NONEMPTY_CLASS_DATA_NO_DECLARING_CLASS')
    field_rows = []; method_rows = []; interface_rows = []; supers = []; source_files = []
    defined_fields = set(); defined_methods = set(); used = set()
    for ordinal, cls in enumerate(classes):
        owner, flags, superclass, interface_off, source_idx, annotation_off, class_data, static_off = cls
        dependencies = [superclass] if superclass != 0xffffffff else []
        supers.append([types[owner], types[superclass] if superclass != 0xffffffff else None])
        source_files.append([ord(c) for c in strings[source_idx]] if source_idx != 0xffffffff else None)
        if interface_off:
            require(interface_off in type_list_starts, 'INTERFACE_LIST_NOT_ITEM_START')
            interfaces = [struct.unpack_from('<H', data, interface_off + 4 + i * 2)[0] for i in range(word(interface_off))]
            require(len(set(interfaces)) == len(interfaces), 'DUPLICATE_INTERFACE')
            interface_rows.extend([types[owner], i, types[index]] for i, index in enumerate(interfaces))
            dependencies.extend(interfaces)
        require(all(positions.get(index, -1) < ordinal for index in dependencies), 'CLASS_DEPENDENCY_ORDER')
        if not class_data:
            continue
        require(class_data in class_data_starts, 'CLASS_DATA_NOT_ITEM_START')
        at = class_data; counts = []
        for _ in range(4):
            value, at = leb(at); counts.append(value)
        require(class_data not in used or not any(counts), 'SHARED_CLASS_DATA'); used.add(class_data)
        for group, count in enumerate(counts):
            previous = 0
            for member_ordinal in range(count):
                delta, at = leb(at); access, at = leb(at)
                is_field = group < 2
                require(member_ordinal == 0 or delta != 0, 'DUPLICATE_FIELD_INDEX' if is_field else 'DUPLICATE_METHOD_INDEX')
                require(previous + delta <= 0xffffffff, 'FIELD_DELTA_OVERFLOW' if is_field else 'METHOD_DELTA_OVERFLOW')
                index = previous + delta; previous = index
                refs = fields if is_field else methods
                require(index < len(refs), 'FIELD_INDEX_OUT_OF_RANGE' if is_field else 'METHOD_INDEX_OUT_OF_RANGE')
                require(refs[index][0] == owner, 'FIELD_OWNER_MISMATCH' if is_field else 'METHOD_OWNER_MISMATCH')
                known = defined_fields if is_field else defined_methods
                require(index not in known, 'DUPLICATE_FIELD_DEFINITION' if is_field else 'DUPLICATE_METHOD_DEFINITION'); known.add(index)
                if is_field:
                    require(bool(access & 8) == (group == 0), 'FIELD_KIND_FLAGS_MISMATCH')
                    field_rows.append([refs[index][1], 'static' if group == 0 else 'instance', member_ordinal, access])
                else:
                    code, at = leb(at)
                    require(bool(access & (8 | 2 | 0x10000)) == (group == 2), 'METHOD_KIND_FLAGS_MISMATCH')
                    require(not (access & (0x100 | 0x400)) or code == 0, 'NATIVE_OR_ABSTRACT_HAS_CODE')
                    require(bool(access & (0x100 | 0x400)) or code != 0, 'CONCRETE_METHOD_MISSING_CODE')
                    body = 'abstract' if access & 0x400 else 'native' if access & 0x100 else 'present'
                    method_rows.append([refs[index][1], 'direct' if group == 2 else 'virtual', member_ordinal, access, body])
    return {'class_order': [types[c[0]] for c in classes], 'fields': sorted(field_rows), 'methods': sorted(method_rows),
            'interfaces': interface_rows, 'superclasses': supers, 'source_files': source_files,
            'reference_only_fields': [value for index, (_, value) in enumerate(fields) if index not in defined_fields],
            'reference_only_methods': [value for index, (_, value) in enumerate(methods) if index not in defined_methods]}


def main():
    manifest = json.loads((HERE / 'manifest.json').read_text())
    expected = json.loads((HERE / 'expected.json').read_text())['definitions-035']
    records = []
    for case in manifest['files']:
        data = (HERE / case['path']).read_bytes()
        require(len(data) == case['bytes'] and hashlib.sha256(data).hexdigest() == case['sha256'], 'FIXTURE_IDENTITY')
        negative = case['expected'][0].isupper()
        try:
            actual = decode(data)
            require(not negative, 'UNEXPECTED_ACCEPT')
            if case['expected'] == 'definition_metadata_complete':
                for key in ['class_order', 'fields', 'methods', 'interfaces', 'superclasses', 'reference_only_fields', 'reference_only_methods']:
                    require(actual[key] == expected[key], 'HAND_EXPECTATION_' + key)
            if case['id'] == 'source-file-surrogate':
                require(actual['source_files'][2] == [0xd800], 'SOURCE_FILE_LOSSLESS')
            records.append({'id': case['id'], 'status': 'passed', 'observed': actual})
        except Invalid as error:
            if not negative or str(error) != case['expected']:
                raise
            records.append({'id': case['id'], 'status': 'rejected_as_expected', 'reason': str(error)})
    print(json.dumps({'oracle': 'independent-python-struct-v1', 'checks': records, 'full_runtime_verification': False}, indent=2))


if __name__ == '__main__':
    main()
