"""Exact AAPT2 tree projection plus an independent raw typed-attribute walk."""
import json
import math
import struct
import zipfile


def compare(native, text, apk, oracle):
    require = oracle.require
    expected = oracle.aapt_tree(text)
    document = native['manifests'][0]['document']
    nodes = document['nodes']
    require(len(nodes) == len(expected), 'Manifest node count differs')
    float_checks, raw_checks, omissions, zero_refs = 0, 0, 0, 0
    with zipfile.ZipFile(apk) as archive:
        members = [item for item in archive.infolist() if item.filename == 'AndroidManifest.xml']
        require(len(members) == 1, 'independent Manifest member is ambiguous')
        raw = archive.read(members[0])
    require(struct.unpack_from('<HHI', raw) == (3, 8, len(raw)), 'AXML root header differs')
    at, native_index = 8, 0
    while at < len(raw):
        kind, header, size = struct.unpack_from('<HHI', raw, at)
        require(size >= header and at + size <= len(raw), 'raw AXML chunk bounds')
        if kind == 0x102:
            require(native_index < len(nodes), 'extra raw start element')
            node = nodes[native_index]
            reference = expected[native_index]
            actual = dict(namespace_uri=node['name']['namespace_uri'], name=node['name']['local_name'],
                          parent=node['parent'], attributes=[])
            start, stride, count = struct.unpack_from('<HHH', raw, at + 24)
            require(stride >= 20 and len(node['attributes']) == count
                    and len(reference['attributes']) == count, 'raw/native/AAPT attribute counts differ')
            for ordinal, attribute in enumerate(node['attributes']):
                offset = at + header + start + ordinal * stride
                require(offset + 20 <= at + size, 'raw attribute out of bounds')
                raw_index = struct.unpack_from('<I', raw, offset + 8)[0]
                value_size, reserved, data_type, bits = struct.unpack_from('<HBBI', raw, offset + 12)
                require(value_size == 8 and reserved == 0, 'invalid independent typed value')
                value = attribute['value']
                require(data_type == value['data_type'] and bits == value['raw_data'], 'typed raw bits differ')
                expected_raw = None if raw_index == 0xffffffff else document['strings'][raw_index]['value']
                require(expected_raw == attribute['raw_value'], 'rawValue string index differs')
                left = reference['attributes'][ordinal]
                raw_value = None if attribute['raw_value'] is None else attribute['raw_value']['text']
                if left['raw'] is None and raw_value == '':
                    left['raw'] = ''
                    omissions += 1
                rendered = oracle.render(value)
                if data_type == 1 and bits == 0:
                    # AAPT aliases a zero resource reference to this display.
                    # Keep native TYPE_REFERENCE distinct from TYPE_NULL; both
                    # type and raw bits have just been checked independently.
                    require(left['rendered'] == '@null', 'zero reference display differs')
                    rendered = '@null'
                    zero_refs += 1
                if data_type == 4:
                    # Do not compare display precision or use epsilon. AAPT's
                    # decimal must re-encode to the exact original float32 bits.
                    number = float(left['rendered'])
                    encoded = struct.unpack('<I', struct.pack('<f', number))[0]
                    is_nan = math.isnan(struct.unpack('<f', struct.pack('<I', bits))[0])
                    require((math.isnan(number) and is_nan) or (not is_nan and encoded == bits),
                            'AAPT float does not encode the original float32 bits')
                    rendered = left['rendered']
                    float_checks += 1
                actual['attributes'].append(dict(namespace_uri=attribute['name']['namespace_uri'],
                    name=attribute['name']['local_name'], resource_id=attribute['resource_id'],
                    raw=raw_value, rendered=rendered))
                raw_checks += 1
            require(actual == reference, 'Manifest tree projection differs at node ' + str(native_index))
            native_index += 1
        at += size
    require(at == len(raw) and native_index == len(nodes), 'raw tree traversal incomplete')
    return dict(nodes=len(nodes), attributes=raw_checks, complete_tree_equal=True,
                independent_raw_typed_attributes=raw_checks, raw_value_indices_verified=True,
                float32_exact_bit_checks=float_checks, aapt_empty_raw_omissions=omissions,
                aapt_zero_reference_null_display=zero_refs,
                float_policy='decimal re-encoding must match exact float32 bits; NaN display plus independent raw payload bits',
                comparison='all ordered element namespace/name/parent and attribute namespace/name/resource ID/raw/typed value')
