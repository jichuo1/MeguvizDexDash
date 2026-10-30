"""Small public/synthetic-only seeds; no APK discovery or private paths."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / 'fuzz' / 'corpus'


def main():
    targets = {name: [] for name in ('archive', 'mutf8_leb', 'header_raw',
                                    'header_repaired', 'code_payload', 'encoded_values')}
    common = sorted((ROOT / 'tests/fixtures/generated').glob('minimal-*.dex'))
    common += [ROOT / 'tests/fixtures/generated' / name
               for name in ('bad-checksum.dex', 'bad-signature.dex', 'bad-map-offset.dex')]
    instructions = sorted((ROOT / 'tests/fixtures/instructions/generated').glob('*.dex'))
    annotations = sorted((ROOT / 'tests/fixtures/annotations/generated').glob('*.dex'))
    # The two five-MiB count fixtures exceed this smoke's explicit 64-KiB scope.
    # Keep their exclusion visible; existing ordinary regression tests own their exact 65k counts.
    excluded = {'count-65535.zip', 'count-65536.zip'}
    zip64 = [p for p in sorted((ROOT / 'tests/fixtures/zip64/generated').glob('*.zip'))
             if p.name not in excluded]
    archive = [ROOT / 'tests/fixtures/generated' / name for name in
               ('multidex-stored.apk', 'multidex-deflated.apk', 'duplicate-name.apk',
                'bad-crc.apk', 'member-policy.apk')]
    if not common or not instructions or not annotations or not zip64:
        raise RuntimeError('required synthetic source family missing')
    for name in ('header_raw', 'header_repaired'):
        targets[name] = common + instructions[:2] + annotations[:2]
    targets['code_payload'] = instructions
    targets['encoded_values'] = annotations
    targets['archive'] = archive + zip64
    records = []
    for target, paths in targets.items():
        directory = DEST / target
        directory.mkdir(parents=True, exist_ok=True)
        for path in paths:
            data = path.read_bytes()
            if len(data) > 65536:
                raise RuntimeError(f'oversize synthetic seed: {path}')
            digest = hashlib.sha256(data).hexdigest()
            out = directory / digest
            out.write_bytes(data)
            records.append(dict(target=target, source=path.relative_to(ROOT).as_posix(),
                                path=out.relative_to(ROOT).as_posix(), bytes=len(data), sha256=digest))
    manual = [b'', b'\x00', b'\x7f', b'\x80\x00', b'\xff\xff\xff\xff\x0f',
              b'\xff\xff\xff\xff\x7f', b'\x80' * 6,
              b'\x01A\x00', b'\x01\xc0\x80\x00', b'\x01\xed\xa0\x80\x00',
              b'\x02\xed\xa0\xbd\xed\xb8\x80\x00', b'\x01\xf0\x90\x80\x80\x00',
              b'\x01\xc1\x81\x00', b'\x01\xe0\x80\x81\x00']
    directory = DEST / 'mutf8_leb'
    directory.mkdir(parents=True, exist_ok=True)
    for index, data in enumerate(manual):
        digest = hashlib.sha256(data).hexdigest()
        out = directory / digest
        out.write_bytes(data)
        records.append(dict(target='mutf8_leb', source=f'handwritten-utf16-leb-vector-{index}',
                            path=out.relative_to(ROOT).as_posix(), bytes=len(data), sha256=digest))
    manifest = dict(schema_version='mdd.fuzz-seeds.v1', private_inputs=False, files=records,
                    excluded_over_budget=sorted(excluded),
                    note='shared synthetic generators are regression seeds, not independent fuzz oracle')
    (ROOT / 'conformance/sanitizers/corpus-manifest.json').write_text(
        json.dumps(manifest, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'seed_records': len(records), 'targets': 6}))


if __name__ == '__main__':
    main()
