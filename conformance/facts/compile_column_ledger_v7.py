#!/usr/bin/env python3
"""Link nonempty partial-reference coverage to a recomputed v6 inventory."""
import datetime
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import compile_column_ledger as base

ROOT=base.ROOT
STAMP=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT=ROOT/'artifacts/mdd-026/column-ledger-v7'/STAMP
SOURCE='artifacts/mdd-026/partial-reference-audit/20261029T021708996807Z'
ROOT_DIR='artifacts/mdd-026/partial-reference-audit'


def load(path):return json.loads((ROOT/path).read_bytes())


def verify_tool(path):
    record=load(path+'/record.json');folder=ROOT/path
    base.require(record['exit_code']==0 and base.sha((folder/'stdout.txt').read_bytes())==record['stdout']['sha256']
                 and base.sha((folder/'stderr.txt').read_bytes())==record['stderr']['sha256'],'command/hash differs: '+path)
    return base.identity(path+'/record.json')


def inspect_partial():
    result=load(SOURCE+'/result.json')
    base.require(result['status']=='passed-nonempty-partial-reference-scope' and result['task_complete_proven'] is False
                 and result['profile_admitted'] is False and result['a0_complete_duplicate_rows']==8
                 and len(result['cases'])==2,'partial result scope differs')
    path=ROOT/'tests/fixtures/partial_reference_boundary/verify.py'
    spec=importlib.util.spec_from_file_location('partial_reference_v7',path);verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
    for name,expected in result['sources'].items():base.require(base.sha((ROOT/name).read_bytes())==expected,'partial source drift: '+name)
    base.require(verifier.common.digest(verifier.common.A0)==result['a0_sha256']==verifier.common.A0_SHA
                 and verifier.common.digest(ROOT/SOURCE/'partial_reference_probe.exe')==result['native_binary_sha256']
                 and verifier.common.digest(ROOT/verifier.FIXTURE)==result['fixture_sha256']==verifier.FIXTURE_SHA,
                 'partial binary or fixture differs')
    records=[]
    for label in ['build','compile','native-partial-0','native-partial-1','a0-full-two-sources']:
        path=SOURCE+'/'+label;record=load(path+'/record.json')
        base.require(record['exit_code']==0 and record['timed_out'] is False,'partial process failed: '+label)
        base.verify_receipt(record,(ROOT/path/'stdout.txt').read_bytes(),(ROOT/path/'stderr.txt').read_bytes(),False)
        records.append(base.identity(path+'/record.json'))
    full_run=verify_tool(ROOT_DIR+'/first-run-command')
    base.require(load(ROOT_DIR+'/first-run-command/stdout.txt')['path']==SOURCE,'partial run path differs')
    rb=verify_tool(SOURCE+'/readback-command');readback=load(SOURCE+'/readback-command/stdout.txt')
    base.require(readback['status']=='passed' and readback['result_sha256']==base.identity(SOURCE+'/result.json')['sha256']
                 and readback['readback_source_sha256']==base.identity('tests/fixtures/partial_reference_boundary/readback.py')['sha256']
                 and readback['task_complete_proven'] is False and readback['partial_orders']==2,'partial readback differs')
    neg=verify_tool(ROOT_DIR+'/negative-controls')
    base.require(b'8 partial-reference evidence mutations rejected' in (ROOT/ROOT_DIR/'negative-controls/stdout.txt').read_bytes(),
                 'partial negative evidence missing')
    Oracle=verifier.helper.oracle_type();oracle=Oracle((ROOT/verifier.FIXTURE).read_bytes());ref=oracle.read()
    caller=next(x for x in oracle.definitions if x[0]==0);target=next(x for x in oracle.definitions if x[0]==2)
    base.require(caller[3]==420 and target[3]==488 and len(ref['sites'])==10,'partial byte oracle differs')
    cases=[]
    for partial in (0,1):
        value=load(SOURCE+'/native-partial-'+str(partial)+'/stdout.txt');verifier.validate(value,partial)
        sites=[{'caller_method_idx':s['caller_method_idx'],'class_def_idx':s['class_def_idx'],'class_idx':s['class_idx'],
                'pc':s['code_unit_pc'],'operand_ordinal':s['operand_ordinal'],'kind':s['target_kind'],
                'index':s['target_local_index'],'byte_offset':int(s['operand_range']['byte_offset']),
                'byte_length':int(s['operand_range']['byte_length']),'opcode':s['opcode']} for s in value['partial_sites']]
        base.require(sites==ref['sites'] and value['full_method_rows']==[dict(x,file_id=1-partial) for x in ref['relations']['method_calls']],
                     'partial raw sites or full sibling differs')
        target_id=value['partial_local_target'];scope=value['scope'];source=value['partial_source']
        base.require(target_id['snapshot_id']==value['snapshot_id']==scope['snapshot_id']
                     and target_id['dex_occurrence_id']==source['dex_occurrence_id']
                     and source['content_id']=='sha256:'+verifier.FIXTURE_SHA,'partial target identity differs')
        cases.append({'partial_index':partial,'partial_sites':len(sites),
                      'local_match_count':len(value['partial_local_matches']['sites']),
                      'all_facts':value['all_coverage']['facts'],'all_input':value['all_coverage']['input'],
                      'query_error':value['indexed_error']['code'],'valid_subset_covers_all':value['complete_subset']['covers_all_captured_sources']})
    rows=verifier.common.table((ROOT/SOURCE/'a0-full-two-sources/stdout.txt').read_bytes(),verifier.COLS)
    actual=[{k:None if v=='N' else bytes.fromhex(v).decode('utf8','strict') for k,v in row.items()} for row in rows]
    wanted=[{k:str(dict(row,file_id=n)[k]) for k in verifier.COLS} for n in (0,1) for row in ref['relations']['method_calls']]
    verifier.helper.compare(actual,wanted);base.require(len(actual)==8,'A0 full duplicate rows differ')
    return {'result':base.identity(SOURCE+'/result.json'),'readback_command':rb,'full_run_command':full_run,
            'negative_controls':neg,'negative_source':base.identity('tests/fixtures/partial_reference_boundary/test_failures.py'),
            'verified_process_records':records,'cases':cases,
            'scope':'two duplicate synthetic DEX occurrences; nonempty partial references and INCOMPLETE_FACTS retained',
            'limits':['A0 eight rows come from fully loaded inputs and do not qualify partial results',
                      'valid subset does not cover unselected occurrence','no complete HostLab, ART or product profile qualification']}


def main():
    OUT.mkdir(parents=True,exist_ok=False)
    start=datetime.datetime.now(datetime.timezone.utc).isoformat();argv=[sys.executable,'-O','conformance/facts/compile_column_ledger_v6.py']
    proc=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=90)
    (OUT/'base-compiler.stdout.txt').write_bytes(proc.stdout);(OUT/'base-compiler.stderr.txt').write_bytes(proc.stderr)
    (OUT/'base-compiler.record.json').write_text(json.dumps({'argv':argv,'started_utc':start,
        'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':proc.returncode,
        'stdout_sha256':base.sha(proc.stdout),'stderr_sha256':base.sha(proc.stderr)},indent=2)+'\n',encoding='utf8')
    base.require(proc.returncode==0,'v6 recomputation failed; output retained')
    old_path=Path(json.loads(proc.stdout)['path'])/'column-ledger.json';report=load(old_path.as_posix())
    base.require(report['required_relations']==17 and report['required_columns']==156
                 and report['unassembled_projection_columns']==69 and report['task_complete_proven'] is False,'base scope differs')
    report['schema_version']='mdd.scoped-field-evidence-ledger.v7';report['created_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['compiler_source']=base.identity('conformance/facts/compile_column_ledger_v7.py')
    report['base_recomputation']=base.identity(old_path.as_posix())
    report['slices']['nonempty_partial_reference_scope']=inspect_partial()
    counts={'method_calls':0,'method_strings':0,'method_field_accesses':0,'method_used_types':0}
    for column in report['columns']:
        if column['relation'] not in counts: continue
        column['evidence'].append({'slice':'nonempty_partial_reference_scope',
            'type':'required_reference_layer_nonempty_partial_coverage_and_strict_error'})
        column['remaining_boundaries'].append('This slice verifies incomplete reference coverage and strict errors, not complete per-field values or production qualification.')
        counts[column['relation']]+=1
    base.require(counts=={'method_calls':10,'method_strings':8,'method_field_accesses':12,'method_used_types':9}
                 and all(x['full_field_qualification'] is False for x in report['columns']),'field links or qualification differs')
    report['global_remaining'].append('Nonempty partial reference matches do not prove absence or complete all-source results; complete subset excludes the other occurrence.')
    report['is_task_gate']=False;report['task_complete_proven']=False;report['profile_admitted']=False
    (OUT/'column-ledger.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'relations':17,'columns':156,'reference_layer_columns':39,'task_complete_proven':False}))


if __name__=='__main__':main()
