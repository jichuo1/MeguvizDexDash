#!/usr/bin/env python3
"""Independent bounded mixed-source references comparison; does not issue a task gate."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'conformance/facts'))
import verify_definition_projections as common

STAMP = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT = ROOT / 'artifacts/mdd-026/mixed-reference-audit' / STAMP
common.OUT = OUT
FIXTURE = ROOT / 'tests/fixtures/mixed_reference_boundary'


def oracle_type():
    path = ROOT / 'tests/fixtures/references/oracle.py'
    spec = importlib.util.spec_from_file_location('mixed_reference_oracle', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Oracle


def compare_rows(actual, expected):
    common.require(actual == expected, 'A0 ordered complete method_calls multiset differs')


def main():
    common.require(common.A0.is_file() and common.digest(common.A0) == common.A0_SHA, 'A0 binary identity mismatch')
    manifest = json.loads((FIXTURE / 'manifest.json').read_text(encoding='utf-8'))
    entries = {item['id']: item for item in manifest['files']}
    common.require(manifest['scenario'] == ['classic', 'shared', 'classic'], 'scenario differs')
    paths = [FIXTURE / entries[name]['path'] for name in manifest['scenario']]
    for name, path in zip(manifest['scenario'], paths):
        raw = path.read_bytes()
        common.require(len(raw) == entries[name]['bytes'] and hashlib.sha256(raw).hexdigest() == entries[name]['sha256'], 'fixture changed: ' + name)
    sources = ['tests/fixtures/mixed_reference_boundary/generate.py', 'tests/fixtures/mixed_reference_boundary/manifest.json',
               'tests/fixtures/mixed_reference_boundary/probe.rs', 'tests/fixtures/mixed_reference_boundary/verify.py',
               'tests/fixtures/references/oracle.py', 'conformance/facts/verify_definition_projections.py',
               'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml']
    for package in ['mdd-dex', 'mdd-input', 'mdd-types', 'mdd-facts']:
        sources.append(f'crates/{package}/Cargo.toml')
        sources += [p.relative_to(ROOT).as_posix() for p in sorted((ROOT/'crates'/package/'src').rglob('*.rs'))]
    identities = {name: common.digest(ROOT/name) for name in sources}
    build = common.command('build', ['cargo', 'build', '-p', 'mdd-facts', '--lib', '--jobs', '1', '--locked', '--offline', '--message-format=json'])
    libraries = {}
    for line in build.splitlines():
        item = json.loads(line)
        if item.get('reason') == 'compiler-artifact':
            files = [name for name in item.get('filenames', []) if name.endswith('.rlib')]
            if len(files) == 1:
                libraries[item['target']['name']] = files[0]
    exe = OUT/'mixed_reference_probe.exe'
    argv = ['rustc', '--edition=2024', '--crate-name', 'mdd_mixed_reference_probe', sources[2], '-L', 'dependency=target/debug/deps', '-o', exe]
    for name in ['mdd_dex', 'mdd_facts', 'mdd_input', 'mdd_types', 'serde_json']:
        common.require(name in libraries, 'missing Cargo artifact ' + name)
        argv += ['--extern', name+'='+libraries[name]]
    common.command('compile', argv)
    native = json.loads(common.command('native', [exe, *paths]))
    common.require(native['probe_complete'] and native['operation_status'] == 'ok' and len(native['occurrences']) == 3, 'native incomplete')
    common.require(native['class_resolution']['status'] == 'ambiguous' and len(native['class_resolution']['matches']) == 3, 'same descriptor definitions not ambiguous')
    common.require(native['cross_occurrence_error']['code'] == 'INVALID_ARGUMENT', 'foreign occurrence did not fail')
    Oracle = oracle_type()
    sql_columns = ['file_id','method','method_class','method_name','class_idx','method_idx','callee','callee_class','callee_name','callee_method_idx']
    sql = 'SELECT ' + ','.join(f'''CASE WHEN "{col}" IS NULL THEN 'N' ELSE hex(CAST("{col}" AS TEXT)) END AS "{col}"''' for col in sql_columns)
    sql += ' FROM method_calls ORDER BY file_id,method_idx,callee_method_idx,callee'
    args = [value for path in paths for value in ('--input', path)]
    a0 = common.table(common.command('a0-calls', [common.A0, '--threads', '1', 'query', *args, '--sql', sql]), sql_columns)
    a0_rows = [{k: None if v == 'N' else bytes.fromhex(v).decode('utf-8', 'strict') for k,v in row.items()} for row in a0]
    occurrences = native['occurrences']
    common.require([o['selected']['file_id'] for o in occurrences] == [0,1,2], 'source order differs')
    common.require(len({o['source']['dex_occurrence_id'] for o in occurrences}) == 3, 'occurrences merged')
    common.require(occurrences[0]['source']['content_id'] == occurrences[2]['source']['content_id'] != occurrences[1]['source']['content_id'], 'content identity differs')
    common.require(occurrences[0]['pool']['string_pool_id'] == occurrences[2]['pool']['string_pool_id'] != occurrences[1]['pool']['string_pool_id'], 'physical pool identity differs')
    common.require([o['target_index'] for o in occurrences] == [2,3,2], 'local target indices differ')
    shared = [s for s in occurrences[1]['all_sites'] if s['target_kind'] == 'method'
              and s['target_local_index'] == occurrences[1]['target_index']]
    common.require(len(shared) == 2 and {s['caller_method_idx'] for s in shared} == {0, 1}
                   and len({s['code_item_byte_offset'] for s in shared}) == 1
                   and len({s['code_unit_pc'] for s in shared}) == 1,
                   'shared physical code owner occurrences differ')
    expected_rows = []
    expected_sites = []
    expected_global = []
    for number, (name, path, actual) in enumerate(zip(manifest['scenario'], paths, occurrences)):
        ref = Oracle(path.read_bytes()).read()
        source_id = actual['source']['dex_occurrence_id']
        rows = [dict(row, file_id=number) for row in ref['relations']['method_calls']]
        expected_rows += rows
        actual_rows = actual['method_call_rows']
        common.require(actual_rows == rows, 'native method call rows/order differ for ' + name)
        sites = [{ 'caller_method_idx':s['caller_method_idx'], 'class_def_idx':s['class_def_idx'], 'class_idx':s['class_idx'],
                   'pc':s['code_unit_pc'], 'operand_ordinal':s['operand_ordinal'], 'kind':s['target_kind'],
                   'index':s['target_local_index'], 'byte_offset':int(s['operand_range']['byte_offset']),
                   'byte_length':int(s['operand_range']['byte_length']), 'opcode':s['opcode']} for s in actual['all_sites']]
        common.require(sites == ref['sites'], 'source byte operand sites/order differ for ' + name)
        local_expected = [{'caller_method_definition': {'dex_occurrence_id': source_id,
                          'kind':'method_definition', 'local_index':site['caller_method_idx'],
                          'snapshot_id':native['snapshot_id']}, 'code_unit_pc':site['pc'],
                          'operand_kind':'method', 'operand_ordinal':site['operand_ordinal']}
                         for site in ref['sites'] if site['kind'] == 'method' and site['index'] == actual['target_index']]
        common.require(actual['local_target']['sites'] == local_expected, 'local target identity/sites differ')
        expected_global += local_expected
        expected_sites += sites
    common.require(native['global_indexed']['sites'] == expected_global, 'global symbol source/sites differ')
    key = lambda row: (int(row['file_id']), int(row['method_idx']), int(row['callee_method_idx']), row['callee'])
    expected_text = [{k:str(row[k]) for k in sql_columns} for row in sorted(expected_rows, key=key)]
    compare_rows(a0_rows, expected_text)
    mutations = [expected_text[:-1], [dict(expected_text[0], file_id='2'), *expected_text[1:]],
                 [dict(expected_text[0], callee_method_idx='999'), *expected_text[1:]]]
    for changed in mutations:
        try:
            compare_rows(changed, expected_text)
        except RuntimeError as error:
            common.require(str(error) == 'A0 ordered complete method_calls multiset differs', 'unexpected negative terminal')
        else:
            raise RuntimeError('negative mutation accepted')
    common.require(all(common.digest(ROOT/name) == sha for name,sha in identities.items()), 'source changed during run')
    common.require(common.digest(common.A0) == common.A0_SHA, 'A0 changed during run')
    report = {'schema_version':'mdd.mixed-reference-observation.v1', 'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'status':'passed-scoped-mixed-reference-comparison', 'task_complete_proven':False, 'profile_admitted':False,
              'a0_sha256':common.A0_SHA, 'probe_binary_sha256':common.digest(exe), 'sources':identities,
              'fixture_sha256':[entries[name]['sha256'] for name in manifest['scenario']], 'source_occurrences':3,
              'target_local_indices':[o['target_index'] for o in occurrences], 'all_site_count':len(expected_sites),
              'shared_code_target_sites':len(shared), 'shared_code_owner_ids':sorted({s['caller_method_idx'] for s in shared}),
              'a0_method_call_rows':len(a0_rows), 'negative_controls_rejected':3,
              'scope':'three synthetic raw DEX occurrences; exact source sites and complete A0 rows; no runtime dispatch or complete task qualification'}
    (OUT/'result.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(), 'status':report['status'], 'sites':len(expected_sites), 'a0_rows':len(a0_rows), 'task_complete_proven':False}))


if __name__ == '__main__':
    main()
