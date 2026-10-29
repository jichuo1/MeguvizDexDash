#!/usr/bin/env python3
"""Add field/type and dynamic/orphan scoped evidence to a recomputed v4 inventory."""
import datetime
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import compile_column_ledger as base

ROOT = base.ROOT
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT = ROOT/'artifacts/mdd-026/column-ledger-v5'/STAMP
FIELD = 'artifacts/mdd-026/field-type-audit/20261029T010629766313Z'
DYNAMIC = 'artifacts/mdd-026/dynamic-source-audit/20261029T012418079194Z'


def load(path):
    return json.loads((ROOT/path).read_bytes())


def check_terminal(kind,result,native):
    expected_status = 'passed-scoped-field-type-observation' if kind == 'field' else 'passed-scoped-dynamic-source-observation'
    base.require(result['status'] == expected_status and result['task_complete_proven'] is False
                 and result['profile_admitted'] is False and native['operation_status'] == 'ok'
                 and native['probe_complete'] is True and native['profile_admitted'] is False,
                 kind+' scope or terminal differs')
    if kind == 'field':
        base.require(result['source_occurrences'] == 3 and result['field_local_indices'] == [0,1,0]
                     and result['type_local_indices'] == [4,5,4] and result['target_site_counts'] == {'field':6,'type':6}
                     and result['a0_row_counts'] == {'method_field_accesses':7,'method_used_types':6}
                     and result['negative_controls_rejected'] == 6, 'field scope counts differ')
        base.require(all(native[x]['code'] == 'INVALID_ARGUMENT' and native[x]['stage'] == 'facts.references'
                     for x in ['foreign_field','foreign_type']), 'field source errors differ')
    else:
        base.require(result['source_occurrences'] == 4 and result['site_counts'] == [17,13,10,17]
                     and result['dynamic_counts'] == [2,0,0,2] and result['unowned_counts'] == [0,0,1,0]
                     and result['a0_method_call_rows'] == 20 and result['quota_errors'] == 4
                     and result['negative_controls_rejected'] == ['missing_occurrence','wrong_file','bootstrap_as_callee'],
                     'dynamic scope counts differ')
        base.require(native['foreign_call_site']['code'] == 'INVALID_ARGUMENT' and len(native['quota_errors']) == 4
                     and all(x['code'] == 'QUOTA_EXCEEDED' for x in native['quota_errors']), 'dynamic error terminal differs')


def check_sites(actual,oracle):
    mapped = [{'caller_method_idx':s['caller_method_idx'],'class_def_idx':s['class_def_idx'],'class_idx':s['class_idx'],
               'pc':s['code_unit_pc'],'operand_ordinal':s['operand_ordinal'],'kind':s['target_kind'],
               'index':s['target_local_index'],'byte_offset':int(s['operand_range']['byte_offset']),
               'byte_length':int(s['operand_range']['byte_length']),'opcode':s['opcode']} for s in actual]
    base.require(mapped == oracle,'source operand sites/order differ')


def inspect(kind):
    path = FIELD if kind == 'field' else DYNAMIC
    fixture = 'field_type_boundary' if kind == 'field' else 'dynamic_source_boundary'
    result = load(path+'/result.json'); native = load(path+'/native/stdout.txt')
    check_terminal(kind,result,native)
    for source,expected in result['sources'].items():
        base.require(base.sha((ROOT/source).read_bytes()) == expected,kind+' source drift: '+source)
    spec = importlib.util.spec_from_file_location('mdd_v5_'+kind,ROOT/'tests/fixtures'/fixture/'verify.py')
    verifier = importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
    base.require(verifier.common.digest(verifier.common.A0) == result['a0_sha256'] == verifier.common.A0_SHA,
                 kind+' A0 binary differs')
    binary = 'field_type_probe.exe' if kind == 'field' else 'dynamic_source_probe.exe'
    base.require(base.sha((ROOT/path/binary).read_bytes()) == result['native_binary_sha256'],kind+' native binary differs')
    labels = ['build','compile','native']+(['a0-method_field_accesses','a0-method_used_types'] if kind == 'field' else ['a0-method-calls'])
    records = []
    for label in labels:
        d = path+'/'+label;record = load(d+'/record.json')
        base.require(record['exit_code'] == 0 and record['timed_out'] is False,kind+' command failed: '+label)
        base.verify_receipt(record,(ROOT/d/'stdout.txt').read_bytes(),(ROOT/d/'stderr.txt').read_bytes(),False)
        records.append(base.identity(d+'/record.json'))
    rbdir = ROOT/path/'readback-command'
    rb = load(path+'/readback-command/record.json')
    base.require(rb['exit_code'] == 0 and base.sha((rbdir/'stdout.txt').read_bytes()) == rb['stdout']['sha256']
                 and base.sha((rbdir/'stderr.txt').read_bytes()) == rb['stderr']['sha256'],kind+' readback command differs')
    readback = json.loads((rbdir/'stdout.txt').read_bytes())
    base.require(readback['status'] == 'passed' and readback['task_complete_proven'] is False
                 and readback['result_sha256'] == base.identity(path+'/result.json')['sha256']
                 and readback['readback_source_sha256'] == base.identity('tests/fixtures/'+fixture+'/readback.py')['sha256'],
                 kind+' readback source/result differs')
    Oracle = verifier.oracle_type() if kind == 'field' else verifier.helper.oracle_type()
    occ = native['occurrences'];items = verifier.FIXTURES
    base.require(len(occ) == len(items) and len({x['source']['dex_occurrence_id'] for x in occ}) == len(occ),
                 kind+' occurrence identity differs')
    base.require(occ[0]['source']['content_id'] == occ[-1]['source']['content_id']
                 and occ[0]['pool']['string_pool_id'] == occ[-1]['pool']['string_pool_id'],
                 kind+' repeated physical identity differs')
    expected = {'method_field_accesses':[],'method_used_types':[]} if kind == 'field' else {'method_calls':[]}
    for i,((name,sha),item) in enumerate(zip(items,occ)):
        raw = (ROOT/name).read_bytes()
        base.require(base.sha(raw) == sha == result['fixture_sha256'][i] and item['source']['content_id'] == 'sha256:'+sha
                     and item['selected']['file_id'] == i,kind+' source input identity differs')
        oracle = Oracle(raw).read();check_sites(item['sites'],oracle['sites'])
        if kind == 'field':
            for relation,key in [('method_field_accesses','field_rows'),('method_used_types','type_rows')]:
                rows = [dict(x,file_id=i) for x in oracle['relations'][relation]]
                base.require(item[key] == rows,'native '+relation+' differs from oracle');expected[relation].extend(rows)
            for target,label,idx in [('field','field_local',item['field_index']),('type','type_local',item['type_index'])]:
                selected=[s for s in oracle['sites'] if s['kind']==target and s['index']==idx]
                wanted=[{'caller_method_definition':{'dex_occurrence_id':item['source']['dex_occurrence_id'],
                         'kind':'method_definition','local_index':s['caller_method_idx'],'snapshot_id':native['snapshot_id']},
                         'code_unit_pc':s['pc'],'operand_kind':target,'operand_ordinal':s['operand_ordinal']} for s in selected]
                base.require(item[label]['sites']==wanted,'field/type indexed source binding differs')
        else:
            rows=[dict(x,file_id=i) for x in oracle['relations']['method_calls']]
            base.require(item['method_call_rows']==rows,'native dynamic calls differ from oracle');expected['method_calls'].extend(rows)
            base.require(item['coverage']['unowned_physical_code_items']==len(oracle['unowned_code_offsets'])
                         and len(item['dynamic_calls'])==len(oracle['dynamic_calls']),'dynamic/orphan coverage differs')
            for observed,wanted in zip(item['dynamic_calls'],oracle['dynamic_calls']):
                site=item['sites'][observed['site_ordinal']]
                base.require(site['caller_method_idx']==wanted['caller_method_idx'] and site['code_unit_pc']==wanted['pc']
                             and observed['call_site_idx']==wanted['call_site_idx']
                             and 'unknown_dynamic_target' in observed['runtime_target_status'],'dynamic target was inferred')
            base.require(all(x['callee_name'] != 'bootstrap' for x in item['method_call_rows']), 'bootstrap became runtime callee')
            for check,site in zip(item['target_checks'],oracle['sites']):
                target=check['target'];kind_name=site['kind'];idx=site['index']
                base.require(target['kind']==kind_name and target['local_index']==idx
                             and target['dex_occurrence_id']==item['source']['dex_occurrence_id'],'target identity differs')
                wanted=[{'caller_method_definition':{'dex_occurrence_id':item['source']['dex_occurrence_id'],
                         'kind':'method_definition','local_index':s['caller_method_idx'],'snapshot_id':native['snapshot_id']},
                         'code_unit_pc':s['pc'],'operand_kind':kind_name,'operand_ordinal':s['operand_ordinal']}
                        for s in oracle['sites'] if s['kind']==kind_name and s['index']==idx]
                base.require(check['matches']['sites']==wanted,'dynamic indexed/scalar source sites differ')
            base.require(len(item['target_checks']) == len(oracle['sites']),'dynamic target checks incomplete')
    if kind == 'dynamic':
        base.require([s['code_unit_pc'] for s in occ[1]['sites'] if s['target_kind']=='method_handle']==[24,26]
                     and len(occ[1]['method_call_rows'])==4 and len(occ[1]['method_field_rows'])==2,
                     'method handle constant produced false call or field access')
    for relation,rows in expected.items():
        cols = verifier.COLUMNS[relation] if kind == 'field' else verifier.COLS
        label = 'a0-'+relation if kind == 'field' else 'a0-method-calls'
        parsed=verifier.common.table((ROOT/path/label/'stdout.txt').read_bytes(),cols)
        actual=[{k:None if v=='N' else bytes.fromhex(v).decode('utf8','strict') for k,v in row.items()} for row in parsed]
        wanted=[{k:str(row[k]) for k in cols} for row in rows]
        (verifier.compare if kind == 'field' else verifier.helper.compare)(actual,wanted)
    return {'result':base.identity(path+'/result.json'),'readback_command':base.identity(path+'/readback-command/record.json'),
            'verified_process_records':records,'source_occurrences':len(occ),'scope':result['scope'],
            'limits':['A0 rows are multisets and do not prove site PC order','no runtime dispatch, ART or product profile qualification']}


def main():
    OUT.mkdir(parents=True,exist_ok=False)
    start=datetime.datetime.now(datetime.timezone.utc).isoformat();argv=[sys.executable,'-O','conformance/facts/compile_column_ledger_v4.py']
    proc=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=90)
    (OUT/'base-compiler.stdout.txt').write_bytes(proc.stdout);(OUT/'base-compiler.stderr.txt').write_bytes(proc.stderr)
    (OUT/'base-compiler.record.json').write_text(json.dumps({'argv':argv,'started_utc':start,
        'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':proc.returncode,
        'stdout_sha256':base.sha(proc.stdout),'stderr_sha256':base.sha(proc.stderr)},indent=2)+'\n',encoding='utf8')
    base.require(proc.returncode == 0,'v4 recomputation failed; output retained')
    old_path=Path(json.loads(proc.stdout)['path'])/'column-ledger.json';report=load(old_path.as_posix())
    base.require(report['required_relations']==17 and report['required_columns']==156
                 and report['unassembled_projection_columns']==69 and report['task_complete_proven'] is False,'base scope differs')
    report['schema_version']='mdd.scoped-field-evidence-ledger.v5'
    report['created_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['compiler_source']=base.identity('conformance/facts/compile_column_ledger_v5.py')
    report['base_recomputation']=base.identity(old_path.as_posix())
    report['slices']['field_type_multi_source']=inspect('field')
    report['slices']['dynamic_orphan_multi_source']=inspect('dynamic')
    counts={'method_calls':0,'method_field_accesses':0,'method_used_types':0}
    for column in report['columns']:
        relation=column['relation']
        if relation not in counts: continue
        slice_name='dynamic_orphan_multi_source' if relation=='method_calls' else 'field_type_multi_source'
        column['evidence'].append({'slice':slice_name,'type':'source_bound_tiny_dex_bytes_native_and_A0_multisets'})
        column['remaining_boundaries'].append('Multi-source synthetic references observed; A0 rows do not establish PCs, runtime dispatch or complete production coverage.')
        counts[relation]+=1
    base.require(counts=={'method_calls':10,'method_field_accesses':12,'method_used_types':9}
                 and all(x['full_field_qualification'] is False for x in report['columns']),'field links or qualification differs')
    report['global_remaining'].append('Custom call runtime targets remain unknown; method-handle constants and unowned code do not imply calls or owners.')
    report['is_task_gate']=False;report['task_complete_proven']=False;report['profile_admitted']=False
    (OUT/'column-ledger.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'relations':17,'columns':156,
                      'field_type_columns':21,'call_columns':10,'task_complete_proven':False}))


if __name__ == '__main__':
    main()
