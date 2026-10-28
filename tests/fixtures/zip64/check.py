"""Independent Python zipfile consumer of complete positive ZIP64 fixtures."""
from pathlib import Path
import hashlib
import importlib.util
import io
import json
import zipfile

HERE = Path(__file__).resolve().parent


def main():
    manifest = json.loads((HERE / 'manifest.json').read_text())
    spec = importlib.util.spec_from_file_location('fixture_encoder_only', HERE / 'generate.py')
    encoder = importlib.util.module_from_spec(spec); spec.loader.exec_module(encoder)
    reproduced = encoder.fixtures()
    dex = (HERE.parent / 'generated/minimal-035.dex').read_bytes(); other = (HERE.parent / 'generated/structured-035.dex').read_bytes()
    records = []
    for row in manifest['files']:
        data = (HERE / row['path']).read_bytes()
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256'] or data != reproduced[row['id']][0]:
            raise ValueError('fixture is not reproducible: ' + row['id'])
        if row['expected'] != 'ok':
            records.append({'id': row['id'], 'byte_reproduction': True, 'consumer_status': 'negative declaration/layout vector; no format success claimed'})
            continue
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist(); observed = []
            expected_names = (['classes.dex'] + ['r'] * (row['expected_count'] - 1)) if row.get('large_metadata') else [m['name'] for m in row['layout']['members']] if row['layout'] is not None else ['classes.dex']
            if [m.filename for m in members] != expected_names:
                raise ValueError('physical name/ordinal inventory mismatch: ' + row['id'])
            for ordinal, member in enumerate(members):
                value = archive.read(member)
                expected = other if row['id'] == 'duplicate-name' and ordinal == 1 else dex if member.filename.endswith('.dex') else b'' if row.get('large_metadata') else b'\0\xffresource'
                if value != expected:
                    raise ValueError('complete member bytes mismatch: ' + row['id'])
                if not row.get('large_metadata'):
                    observed.append({'ordinal': ordinal, 'name': member.filename, 'size': len(value), 'sha256': hashlib.sha256(value).hexdigest(), 'crc32': member.CRC})
        records.append({'id': row['id'], 'byte_reproduction': True, 'consumer_status': 'fully_consumed', 'member_count': len(members), 'all_ordinals_verified': True, 'members': observed})
    print(json.dumps({'oracle': 'Python stdlib zipfile; no Rust zip implementation shared', 'checks': records,
                      'scope': 'small real ZIP64 positive files plus explicit malformed/quota vectors; not 4GB data or performance qualification'}, indent=2))


if __name__ == '__main__':
    main()
