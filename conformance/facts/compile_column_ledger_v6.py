#!/usr/bin/env python3
"""Link corrupt-sibling coverage evidence to a recomputed v5 inventory."""
import datetime
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import compile_column_ledger as base

ROOT=base.ROOT
STAMP=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT=ROOT/'artifacts/mdd-026/column-ledger-v6'/STAMP
SOURCE='artifacts/mdd-026/mixed-failure-audit/20261029T015522772300Z'
ROOT_DIR='artifacts/mdd-026/mixed-failure-audit'


def load(path): return json.loads((ROOT/path).read_bytes())


def verify_recorded_tool(path,expected_exit):
    record=load(path+'/record.json');d=ROOT/path
    base.require(record['exit_code']==expected_exit and base.sha((d/'stdout.txt').read_bytes())==record['stdout']['sha256']
                 and base.sha((d/'stderr.txt').read_bytes())==record['stderr']['sha256'],'tool command/hash differs: '+path)
    return base.identity(path+'/record.json')


def inspect_failure():
    result=load(SOURCE+'/result.json')
    base.require(result['status']=='passed-scoped-native-failure-coverage' and result['task_complete_proven'] is False
                 and result['profile_admitted'] is False,'mixed failure scope overclaimed')
    fixture=ROOT/'tests/fixtures/mixed_failure_boundary'
    spec=importlib.util.spec_from_file_location('mixed_failure_v6',fixture/'verify.py')
    verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
    for path,expected in result['sources'].items():
        base.require(base.sha((ROOT/path).read_bytes())==expected,'mixed failure source drift: '+path)
    base.require(verifier.common.digest(verifier.common.A0)==result['a0_sha256']==verifier.common.A0_SHA
                 and verifier.common.digest(verifier.SDK)==result['sdk_sha256']==verifier.SDK_SHA
                 and verifier.common.digest(ROOT/SOURCE/'mixed_failure_probe.exe')==result['native_binary_sha256'],
                 'mixed failure binary differs')
    labels=['build','compile','native-valid-first','native-bad-first','a0-good','sdk-bad','a0-valid-first','a0-bad-first']
    records={};identities=[]
    for label in labels:
        path=SOURCE+'/'+label;record=load(path+'/record.json');records[label]=record
        base.verify_receipt(record,(ROOT/path/'stdout.txt').read_bytes(),(ROOT/path/'stderr.txt').read_bytes(),
                            record['exit_code'] != 0)
        if label in ['build','compile','native-valid-first','native-bad-first','a0-good']:
            base.require(record['exit_code']==0 and record['timed_out'] is False,'required command failed: '+label)
        identities.append(base.identity(path+'/record.json'))
    reference=verify_recorded_tool(ROOT_DIR+'/fifth-run-command',0)
    ref_stdout=load(ROOT_DIR+'/fifth-run-command/stdout.txt')
    base.require(ref_stdout['path']==SOURCE and ref_stdout['task_complete_proven'] is False,'source output path differs')
    readback=verify_recorded_tool(SOURCE+'/readback-command',0)
    rb=load(SOURCE+'/readback-command/stdout.txt')
    base.require(rb['status']=='passed' and rb['result_sha256']==base.identity(SOURCE+'/result.json')['sha256']
                 and rb['readback_source_sha256']==base.identity('tests/fixtures/mixed_failure_boundary/readback.py')['sha256']
                 and rb['task_complete_proven'] is False and rb['two_source_orders'] is True,'mixed failure readback differs')
    negatives=verify_recorded_tool(ROOT_DIR+'/negative-controls',0)
    base.require(b'7 mixed-failure evidence mutations rejected' in (ROOT/ROOT_DIR/'negative-controls/stdout.txt').read_bytes(),
                 'negative control execution missing')
    failures=[verify_recorded_tool(ROOT_DIR+'/'+label,1) for label in ['first-run-command','second-run-command','third-run-command']]
    for name,fixture_id in [('good',verifier.VALID),('bad',verifier.BAD)]:
        base.require(base.sha((ROOT/fixture_id[0]).read_bytes())==fixture_id[1],'mixed failure fixture differs: '+name)
    raw=(ROOT/verifier.BAD[0]).read_bytes()
    base.require(struct.unpack_from('<H',raw,462)[0]==65535 and struct.unpack_from('<I',raw,88)[0]==4,
                 'bad index byte proof differs')
    Oracle=verifier.helper.oracle_type()
    try: Oracle(raw).read()
    except ValueError as error: base.require(str(error)=='invalid_code_operand','byte oracle terminal differs')
    else: raise RuntimeError('bad input accepted by byte oracle')
    valid=Oracle((ROOT/verifier.VALID[0]).read_bytes()).read()
    observations=[]
    for label,good,bad in [('valid-first',0,1),('bad-first',1,0)]:
        native=load(SOURCE+'/native-'+label+'/stdout.txt')
        verifier.validate(native,good,bad,verifier.BAD[1])
        base.require(native['valid_method_calls']==[dict(row,file_id=good) for row in valid['relations']['method_calls']]
                     and len(native['valid_reference_sites'])==len(valid['sites'])==10,'valid sibling facts differ')
        observations.append({'case':label,'error_code':native['all_terminal']['code'],
            'error_stage':native['all_terminal']['stage'],'error_details':native['original_error']['details'],
            'all_input':native['all_coverage']['input'],'all_facts':native['all_coverage']['facts'],
            'valid_subset_covers_all':native['valid_subset_coverage']['covers_all_captured_sources']})
    sdk=records['sdk-bad'];sdk_observation=result['sdk_bad_observation']
    base.require(sdk['exit_code']==sdk_observation['exit_code'] and sdk['timed_out']==sdk_observation['timed_out']
                 and (b'<method?>' in (ROOT/SOURCE/'sdk-bad/stdout.txt').read_bytes())==sdk_observation['bad_operand_placeholder_observed'],
                 'SDK actual observation differs')
    a0=[]
    for i,label in enumerate(['a0-valid-first','a0-bad-first']):
        record=records[label];observed=result['a0_bad_observations'][i]
        base.require(record['exit_code']==observed['exit_code'] and record['timed_out']==observed['timed_out'],
                     'A0 actual terminal differs')
        if record['exit_code']==0 and not record['timed_out']:
            rows=verifier.common.table((ROOT/SOURCE/label/'stdout.txt').read_bytes(),verifier.COLS);counts={}
            for row in rows:
                fid=str(int(bytes.fromhex(row['file_id']).decode('ascii')));counts[fid]=counts.get(fid,0)+1
            base.require(counts==observed['rows_by_file'],'A0 observed row count differs')
        a0.append(observed)
    good_rows=verifier.common.table((ROOT/SOURCE/'a0-good/stdout.txt').read_bytes(),verifier.COLS)
    actual=[{k:None if v=='N' else bytes.fromhex(v).decode('utf8','strict') for k,v in row.items()} for row in good_rows]
    expected=[{k:str(row[k]) for k in verifier.COLS} for row in valid['relations']['method_calls']]
    verifier.helper.compare(actual,expected)
    return {'result':base.identity(SOURCE+'/result.json'),'readback_command':readback,'full_run_command':reference,
            'negative_controls':negatives,'prior_failed_commands':failures,'verified_process_records':identities,
            'observations':observations,'sdk_bad_observation':sdk_observation,'a0_bad_observations':a0,
            'scope':'two input orders of one valid and one invalid synthetic DEX; coverage preserves actual producer error',
            'limits':['SDK/A0 outcomes on damaged input are observations only, not valid full audit success',
                      'subset completeness does not cover the unselected source','no full HostLab, ART or product profile qualification']}


def main():
    OUT.mkdir(parents=True,exist_ok=False)
    start=datetime.datetime.now(datetime.timezone.utc).isoformat();argv=[sys.executable,'-O','conformance/facts/compile_column_ledger_v5.py']
    proc=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=90)
    (OUT/'base-compiler.stdout.txt').write_bytes(proc.stdout);(OUT/'base-compiler.stderr.txt').write_bytes(proc.stderr)
    (OUT/'base-compiler.record.json').write_text(json.dumps({'argv':argv,'started_utc':start,
        'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':proc.returncode,
        'stdout_sha256':base.sha(proc.stdout),'stderr_sha256':base.sha(proc.stderr)},indent=2)+'\n',encoding='utf8')
    base.require(proc.returncode==0,'v5 recomputation failed; output retained')
    old_path=Path(json.loads(proc.stdout)['path'])/'column-ledger.json';report=load(old_path.as_posix())
    base.require(report['required_relations']==17 and report['required_columns']==156
                 and report['unassembled_projection_columns']==69 and report['task_complete_proven'] is False,'base scope differs')
    report['schema_version']='mdd.scoped-field-evidence-ledger.v6';report['created_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['compiler_source']=base.identity('conformance/facts/compile_column_ledger_v6.py')
    report['base_recomputation']=base.identity(old_path.as_posix())
    report['slices']['mixed_invalid_reference_scope']=inspect_failure()
    counts={'method_calls':0,'method_strings':0,'method_field_accesses':0,'method_used_types':0}
    for column in report['columns']:
        if column['relation'] not in counts: continue
        column['evidence'].append({'slice':'mixed_invalid_reference_scope',
            'type':'required_reference_layer_corrupt_sibling_coverage_and_exact_error'})
        column['remaining_boundaries'].append('This slice verifies failure propagation for the required reference layer, not each field value or complete production coverage.')
        counts[column['relation']]+=1
    base.require(counts=={'method_calls':10,'method_strings':8,'method_field_accesses':12,'method_used_types':9}
                 and all(x['full_field_qualification'] is False for x in report['columns']),'field links or qualification differs')
    report['global_remaining'].append('Invalid source error remains INVALID_INPUT; SDK/A0 accepting this corrupt operand does not qualify it or prove complete coverage.')
    report['is_task_gate']=False;report['task_complete_proven']=False;report['profile_admitted']=False
    (OUT/'column-ledger.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'relations':17,'columns':156,'reference_layer_columns':39,'task_complete_proven':False}))


if __name__=='__main__': main()
