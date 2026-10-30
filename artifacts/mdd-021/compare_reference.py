"""Finite metadata comparison, not SQL/profile or performance qualification."""
from pathlib import Path
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
BINARY = Path(r'D:\Bilibili_Innocent_Lab\tools\hostlab\vendor\dexsql\0.1.0\dexsql-windows-amd64.exe')
PIN = 'f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def normalized(rows):
    return sorted(json.dumps({k: None if v is None else str(v) for k, v in row.items()}, sort_keys=True, separators=(',', ':')) for row in rows)


def main():
    require(hashlib.sha256(BINARY.read_bytes()).hexdigest() == PIN, 'reference binary identity changed')
    data = json.loads((OUT / 'observed-rust-definitions.json').read_text())
    expected = {}
    expected['classes'] = []
    for row in data['classes']:
        source = row['source_file']
        source = bytes(x for unit in source['utf16_units'] for x in [unit & 255, unit >> 8]).decode('utf-16-le') if source else None
        expected['classes'].append({'file_id': 0, 'class_def_idx': row['class_def_idx'], 'class_idx': row['class_idx'], 'descriptor': row['descriptor'], 'access_flags': row['access_flags'], 'superclass_descriptor': row['superclass_descriptor'], 'interface_count': sum(i['class_idx'] == row['class_idx'] for i in data['interfaces']), 'source_file': source})
    expected['class_interfaces'] = [{k: row[k] for k in ['class_idx', 'ordinal', 'interface_type_idx', 'interface_descriptor']} | {'file_id': 0} for row in data['interfaces']]
    expected['class_fields'] = []
    for row in data['field_definitions']:
        ref = data['field_references'][row['field_idx']]
        expected['class_fields'].append({'file_id': 0, 'class_idx': row['class_idx'], 'class_descriptor': ref['class_descriptor'], 'field_idx': row['field_idx'], 'field_name': ref['field_name'], 'field_descriptor': ref['descriptor'], 'kind': row['kind'], 'access_flags': row['access_flags']})
    expected['class_methods'] = []
    for row in data['method_definitions']:
        ref = data['method_references'][row['method_idx']]
        expected['class_methods'].append({'file_id': 0, 'class_idx': row['class_idx'], 'class_descriptor': ref['class_descriptor'], 'method_idx': row['method_idx'], 'method_name': ref['method_name'], 'method_descriptor': ref['descriptor'], 'kind': row['kind'], 'access_flags': row['access_flags']})
    expected['fields'] = [{'file_id': 0, 'field_idx': row['field_idx'], 'class_idx': row['class_idx'], 'class_descriptor': row['class_descriptor'], 'type_idx': row['type_idx'], 'type_descriptor': row['type_descriptor'], 'name': row['field_name'], 'descriptor': row['descriptor']} for row in data['field_references']]
    definitions = {m['method_idx']: m for m in data['method_definitions']}
    expected['methods'] = []
    for row in data['method_references']:
        definition = definitions.get(row['method_idx'])
        expected['methods'].append({'file_id': 0, 'method_idx': row['method_idx'], 'class_idx': row['class_idx'], 'class_descriptor': row['class_descriptor'], 'proto_idx': row['proto_idx'], 'name': row['method_name'], 'descriptor': row['descriptor'], 'return_descriptor': row['return_descriptor'], 'param_count': len(row['parameter_descriptors']), 'access_flags': definition['access_flags'] if definition else None, 'method_kind': definition['kind'] if definition else None})
    fixture = ROOT / 'tests/fixtures/definitions/generated/definitions-035.dex'
    records = []
    for relation, rows in expected.items():
        columns = list(rows[0])
        projected = ','.join('CASE WHEN "' + name + '" IS NULL THEN \'N\' ELSE hex(CAST("' + name + '" AS TEXT)) END AS "' + name + '"' for name in columns)
        sql = 'SELECT ' + projected + ' FROM ' + relation + ' ORDER BY file_id'
        command = [str(BINARY), '--threads', '1', 'query', '--input', str(fixture), '--sql', sql]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        (OUT / (relation + '-reference-stdout.txt')).write_text(result.stdout, encoding='utf-8')
        (OUT / (relation + '-reference-stderr.txt')).write_text(result.stderr, encoding='utf-8')
        require(result.returncode == 0, relation + ' reference failed: ' + result.stderr)
        observed = []
        saw_header = False
        for line in result.stdout.splitlines():
            if not line.startswith('|'):
                continue
            cells = [cell.strip() for cell in line[1:-1].split('|')]
            if not saw_header:
                require(cells == columns, 'reference projection columns changed')
                saw_header = True
                continue
            require(len(cells) == len(columns), 'reference table framing mismatch')
            observed.append(dict(zip(columns, [None if c == 'N' else bytes.fromhex(c).decode('utf-8', 'strict') for c in cells])))
        require(saw_header, 'reference header missing')
        equal = normalized(rows) == normalized(observed)
        records.append({'relation': relation, 'columns': columns, 'expected_rows': len(rows), 'observed_rows': len(observed), 'equal_multiset': equal, 'command': command, 'exit_code': result.returncode, 'expected': rows, 'observed': observed})
    report = {'scope': 'finite definition metadata fields only; no full SQL, opcode, HostLab, ordering or performance qualification', 'reference_binary_sha256': PIN, 'fixture_sha256': hashlib.sha256(fixture.read_bytes()).hexdigest(), 'comparisons': records, 'complete': all(r['equal_multiset'] for r in records)}
    (OUT / 'reference-comparison.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    require(report['complete'], 'metadata relation differs from fixed reference; retain raw evidence')
    print(json.dumps({'relations_compared': len(records), 'rows_compared': sum(r['observed_rows'] for r in records), 'equal_multisets': True}))


if __name__ == '__main__':
    main()
