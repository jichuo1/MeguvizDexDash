#!/usr/bin/env python3
"""Check the actual CLI vertical slice, including duplicate provenance and errors."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    validator = Draft202012Validator(json.loads((ROOT/'contracts/result.schema.json').read_text(encoding='utf-8')))
    results = []
    for operation, name, count in [
        ('inspect-dex','minimal-035.dex',1), ('inspect-dex','structured-035.dex',1),
        ('inspect-apk','multidex-stored.apk',2), ('inspect-apk','multidex-deflated.apk',2),
        ('inspect-apk','duplicate-content.apk',2),
    ]:
        path = ROOT/'tests/fixtures/generated'/name
        process = subprocess.run([str(binary),operation,str(path)], capture_output=True,check=True)
        value = json.loads(process.stdout)
        validator.validate(value)
        require(value['operation_status'] == 'ok', 'inspection request failed')
        require(value['execution']['complete'] and not value['response']['more_available'], 'inspection computation or delivery incomplete')
        rows = value['data']['rows']
        require(len(rows) == count and value['response']['emitted_rows'] == str(count), 'row count mismatch')
        require(all(not row['header']['full_dex_validation_complete'] for row in rows), 'premature full-format claim')
        require(all(row['header']['signature_verified'] for row in rows), 'required DEX SHA-1 signature verification missing')
        require(len({row['dex_occurrence_id'] for row in rows}) == count, 'logical input multiplicity lost')
        source = value['data']['snapshot_manifest']['sources'][0]
        require(source['content_id'] == 'sha256:'+hashlib.sha256(path.read_bytes()).hexdigest(), 'captured source digest mismatch')
        if name == 'duplicate-content.apk':
            require(rows[0]['content_id'] == rows[1]['content_id'], 'duplicate-content fixture bytes differ')
            require(rows[0]['member']['archive_member_ordinal'] != rows[1]['member']['archive_member_ordinal'], 'physical member occurrences collapsed')
        results.append({'input':name,'rows':count,'status':'passed'})
    for operation, name, code in [
        ('inspect-dex','bad-map-offset.dex','INVALID_INPUT'),
        ('inspect-dex','bad-signature.dex','INVALID_INPUT'),
        ('inspect-dex','unsupported-036.dex','UNSUPPORTED_CAPABILITY'),
        ('inspect-dex','unsupported-041.dex','UNSUPPORTED_CAPABILITY'),
        ('inspect-apk','bad-crc.apk','INVALID_INPUT'),
        ('inspect-apk','duplicate-name.apk','AMBIGUOUS_ENTITY'),
    ]:
        process = subprocess.run([str(binary),operation,str(ROOT/'tests/fixtures/generated'/name)],capture_output=True,check=False)
        require(process.returncode != 0 and not process.stdout, 'invalid input returned successful stdout')
        error = json.loads(process.stderr)
        require(error['code'] == code, 'error category mismatch: '+str(error))
        results.append({'input':name,'expected_error':code,'status':'passed'})
    print(json.dumps({'checks':results,'scope':'header/inventory vertical slice only; no audit qualification'},indent=2))


if __name__ == '__main__':
    main()
