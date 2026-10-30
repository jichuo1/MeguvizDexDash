#!/usr/bin/env python3
"""Link scoped mixed-source references to a recomputed v3 evidence inventory."""
import datetime
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import compile_column_ledger as base

ROOT = base.ROOT
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT = ROOT/'artifacts/mdd-026/column-ledger-v4'/STAMP
SOURCE = 'artifacts/mdd-026/mixed-reference-audit/20261029T004552809470Z'
READBACK = SOURCE+'/readbacks/20261029T004707459234Z/result.json'
GENERATION = 'artifacts/mdd-026/mixed-reference-audit/20261028T175433944682Z/generate'


def load(path):
    return json.loads((ROOT/path).read_text(encoding='utf8'))


def validate_scope(result, native):
    base.require(result['status'] == 'passed-scoped-mixed-reference-comparison'
                 and result['task_complete_proven'] is False and result['profile_admitted'] is False,
                 'mixed-reference scope overclaimed')
    base.require(result['source_occurrences'] == 3 and result['target_local_indices'] == [2,3,2]
                 and result['all_site_count'] == 40 and result['a0_method_call_rows'] == 16
                 and result['shared_code_target_sites'] == 2 and result['shared_code_owner_ids'] == [0,1]
                 and result['negative_controls_rejected'] == 3, 'mixed-reference observed counts differ')
    base.require(native['operation_status'] == 'ok' and native['probe_complete'] is True
                 and native['cross_occurrence_error']['code'] == 'INVALID_ARGUMENT'
                 and native['cross_occurrence_error']['stage'] == 'facts.references',
                 'mixed-reference terminal differs')


def inspect_mixed():
    result = load(SOURCE+'/result.json')
    native = load(SOURCE+'/native/stdout.txt')
    validate_scope(result,native)
    readback = load(READBACK)
    rb_record = load(SOURCE+'/root-readback-command/record.json')
    base.require(readback['status'] == 'passed' and readback['task_complete_proven'] is False
                 and readback['result_sha256'] == base.identity(SOURCE+'/result.json')['sha256']
                 and readback['source_occurrences'] == 3 and readback['site_count'] == 40
                 and readback['a0_method_call_rows'] == 16 and readback['shared_physical_code_owners'] == 2,
                 'mixed-reference readback differs')
    rbdir = ROOT/SOURCE/'root-readback-command'
    base.require(rb_record['exit_code'] == 0 and base.sha((rbdir/'stdout.txt').read_bytes()) == rb_record['stdout']['sha256']
                 and base.sha((rbdir/'stderr.txt').read_bytes()) == rb_record['stderr']['sha256'],
                 'mixed-reference readback command differs')
    base.require(json.loads((rbdir/'stdout.txt').read_bytes()) == readback
                 and readback['readback_source_sha256'] == base.identity('tests/fixtures/mixed_reference_boundary/readback.py')['sha256'],
                 'mixed-reference readback source or output differs')
    records = []
    for path in [GENERATION]+[SOURCE+'/'+label for label in ['build','compile','native','a0-calls']]:
        record = load(path+'/record.json')
        base.require(record['exit_code'] == 0, 'mixed-reference process failed: '+path)
        base.verify_receipt(record,(ROOT/path/'stdout.txt').read_bytes(),(ROOT/path/'stderr.txt').read_bytes(),False)
        records.append(base.identity(path+'/record.json'))
    for path, expected in result['sources'].items():
        base.require(base.sha((ROOT/path).read_bytes()) == expected, 'mixed-reference source drift: '+path)
    fixture = ROOT/'tests/fixtures/mixed_reference_boundary'
    spec = importlib.util.spec_from_file_location('mdd_mixed_v4',fixture/'verify.py')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    base.require(verifier.common.digest(verifier.common.A0) == verifier.common.A0_SHA == result['a0_sha256'],
                 'mixed-reference A0 binary differs')
    base.require(verifier.common.digest(ROOT/SOURCE/'mixed_reference_probe.exe') == result['probe_binary_sha256'],
                 'mixed-reference native binary differs')
    manifest = load('tests/fixtures/mixed_reference_boundary/manifest.json')
    entries = {x['id']:x for x in manifest['files']}
    generator_path = ROOT/'tests/fixtures/references/generate.py'
    base.require(base.sha(generator_path.read_bytes()) == manifest['source_generator_sha256'], 'source generator changed')
    spec = importlib.util.spec_from_file_location('mdd_mixed_v4_generator',generator_path)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    occurrences = native['occurrences']
    base.require(manifest['scenario'] == ['classic','shared','classic'] and len(occurrences) == 3
                 and len({o['source']['dex_occurrence_id'] for o in occurrences}) == 3,
                 'mixed-source occurrence identity differs')
    base.require([o['target_index'] for o in occurrences] == [2,3,2]
                 and [o['selected']['file_id'] for o in occurrences] == [0,1,2], 'mixed-source coordinates differ')
    base.require(occurrences[0]['source']['content_id'] == occurrences[2]['source']['content_id']
                 != occurrences[1]['source']['content_id'], 'mixed-source content identity differs')
    base.require(occurrences[0]['pool']['string_pool_id'] == occurrences[2]['pool']['string_pool_id']
                 != occurrences[1]['pool']['string_pool_id'], 'mixed-source pool identity differs')
    base.require(native['class_resolution']['status'] == 'ambiguous'
                 and len(native['class_resolution']['matches']) == 3, 'class resolution multiplicity differs')
    expected_rows = []
    expected_global = []
    total_sites = 0
    Oracle = verifier.oracle_type()
    for i,(name,actual) in enumerate(zip(manifest['scenario'],occurrences)):
        raw = (fixture/entries[name]['path']).read_bytes()
        rebuilt,_ = generator.build(entries[name]['source_recipe'])
        base.require(raw == rebuilt and base.sha(raw) == entries[name]['sha256'] == result['fixture_sha256'][i], 'mixed fixture differs')
        independent = Oracle(raw).read()
        rows = [dict(row,file_id=i) for row in independent['relations']['method_calls']]
        base.require(actual['method_call_rows'] == rows, 'native method call rows differ from independent oracle')
        expected_rows.extend(rows)
        sites = [{'caller_method_idx':s['caller_method_idx'], 'class_def_idx':s['class_def_idx'], 'class_idx':s['class_idx'],
                  'pc':s['code_unit_pc'], 'operand_ordinal':s['operand_ordinal'], 'kind':s['target_kind'],
                  'index':s['target_local_index'], 'byte_offset':int(s['operand_range']['byte_offset']),
                  'byte_length':int(s['operand_range']['byte_length']), 'opcode':s['opcode']} for s in actual['all_sites']]
        base.require(sites == independent['sites'], 'operand sites differ from source bytes')
        total_sites += len(sites)
        source_id = actual['source']['dex_occurrence_id']
        local = [{'caller_method_definition':{'dex_occurrence_id':source_id,'kind':'method_definition',
                   'local_index':s['caller_method_idx'],'snapshot_id':native['snapshot_id']},
                  'code_unit_pc':s['pc'],'operand_kind':'method','operand_ordinal':s['operand_ordinal']}
                 for s in independent['sites'] if s['kind'] == 'method' and s['index'] == actual['target_index']]
        base.require(actual['local_target']['sites'] == local, 'local target source/sites differ')
        expected_global.extend(local)
    base.require(total_sites == 40 and native['global_indexed']['sites'] == expected_global,
                 'global index source/sites differ')
    shared = [s for s in occurrences[1]['all_sites'] if s['target_kind'] == 'method'
              and s['target_local_index'] == occurrences[1]['target_index']]
    base.require(len(shared) == 2 and {s['caller_method_idx'] for s in shared} == {0,1}
                 and len({s['code_item_byte_offset'] for s in shared}) == 1, 'shared code owner differs')
    columns = ['file_id','method','method_class','method_name','class_idx','method_idx','callee','callee_class','callee_name','callee_method_idx']
    rows = verifier.common.table((ROOT/SOURCE/'a0-calls/stdout.txt').read_bytes(),columns)
    observed = [{k:None if v == 'N' else bytes.fromhex(v).decode('utf8','strict') for k,v in row.items()} for row in rows]
    key = lambda row:(int(row['file_id']),int(row['method_idx']),int(row['callee_method_idx']),row['callee'])
    expected = [{k:str(row[k]) for k in columns} for row in sorted(expected_rows,key=key)]
    verifier.compare_rows(observed,expected)
    return {'result':base.identity(SOURCE+'/result.json'),'readback':base.identity(READBACK),
            'readback_command':base.identity(SOURCE+'/root-readback-command/record.json'),
            'verified_process_records':records,'source_count':3,'site_count':40,'a0_method_call_rows':16,
            'target_local_indices':[2,3,2], 'shared_physical_code_owners':2,
            'scope':'three synthetic occurrences; encoded reference sites and complete A0 call rows',
            'limits':['native indexed/scalar agree only for tested scope; runtime dispatch not inferred',
                      'A0 rows do not expose individual call-site PCs',
                      'no production relation/profile or complete MDD-026 qualification']}


def main():
    OUT.mkdir(parents=True,exist_ok=False)
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    args = [sys.executable,'-O','conformance/facts/compile_column_ledger_v3.py']
    proc = subprocess.run(args,cwd=ROOT,capture_output=True,timeout=90)
    (OUT/'base-compiler.stdout.txt').write_bytes(proc.stdout)
    (OUT/'base-compiler.stderr.txt').write_bytes(proc.stderr)
    (OUT/'base-compiler.record.json').write_text(json.dumps({'argv':args,'started_utc':start,
        'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':proc.returncode,
        'stdout_sha256':base.sha(proc.stdout),'stderr_sha256':base.sha(proc.stderr)},indent=2)+'\n',encoding='utf8')
    base.require(proc.returncode == 0,'v3 ledger recomputation failed; output retained')
    old_path = Path(json.loads(proc.stdout)['path'])/'column-ledger.json'
    report = load(old_path.as_posix())
    base.require(report['required_relations'] == 17 and report['required_columns'] == 156
                 and report['unassembled_projection_columns'] == 69 and report['task_complete_proven'] is False,
                 'base denominator or scope differs')
    evidence = inspect_mixed()
    report['schema_version'] = 'mdd.scoped-field-evidence-ledger.v4'
    report['created_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['compiler_source'] = base.identity('conformance/facts/compile_column_ledger_v4.py')
    report['base_recomputation'] = base.identity(old_path.as_posix())
    report['slices']['mixed_reference_occurrences'] = evidence
    calls, classes = 0, 0
    for column in report['columns']:
        if column['relation'] == 'method_calls':
            column['evidence'].append({'slice':'mixed_reference_occurrences',
                'type':'three_occurrences_ordered_native_source_bytes_and_A0_complete_calls'})
            column['remaining_boundaries'].append('Mixed synthetic call sites and source-local IDs observed; production compatibility and broader source coverage remain unqualified.')
            calls += 1
        if column['relation'] == 'classes' and column['name'] in ['file_id','class_def_idx','class_idx','descriptor']:
            column['evidence'].append({'slice':'mixed_reference_occurrences',
                'type':'three_ambiguous_duplicate_class_definition_identities'})
            classes += 1
    base.require(calls == 10 and classes == 4 and all(x['full_field_qualification'] is False for x in report['columns']),
                 'field links or qualification differ')
    report['global_remaining'].append('A0 method_calls rows do not prove instruction site PCs or runtime dispatch; native sites retain occurrence identity.')
    report['is_task_gate'] = False
    report['task_complete_proven'] = False
    report['profile_admitted'] = False
    (OUT/'column-ledger.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'relations':17,'columns':156,
                      'call_columns':calls,'class_identity_columns':classes,'task_complete_proven':False}))


if __name__ == '__main__':
    main()
