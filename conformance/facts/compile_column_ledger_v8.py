#!/usr/bin/env python3
"""Add duplicate physical resource evidence without upgrading field qualification."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import compile_column_ledger as base

ROOT=base.ROOT
STAMP=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT=ROOT/'artifacts/mdd-026/column-ledger-v8'/STAMP
SOURCE='artifacts/mdd-026/resource-scope-audit/20261029T043749212277Z'
ROOT_READBACK='artifacts/mdd-026/resource-scope-audit/root-readback-20261029'
NEGATIVE=SOURCE+'/readbacks/20261029T043834808830Z'


def load(path):return json.loads((ROOT/path).read_bytes())


def record(path,kind):
    data=load(path+'/record.json');folder=ROOT/path
    base.require(data['exit_code']==0 and not data.get('timed_out',False),'command failed: '+path)
    for name in ('stdout','stderr'):
        key=data[name]['sha256'] if kind=='root' else data[name+'_sha256']
        base.require(base.sha((folder/(name+'.txt')).read_bytes())==key,'output drift: '+path+'/'+name)
    return base.identity(path+'/record.json')


def inspect_resource():
    result=load(SOURCE+'/result.json')
    base.require(result['status']=='passed-synthetic-resource-scope' and result['task_complete_proven'] is False
                 and result['profile_admitted'] is False and result['source_occurrences']==2
                 and result['resource_occurrences']==6,'resource scope differs')
    path=ROOT/'tests/fixtures/resource_scope_boundary/verify.py'
    spec=importlib.util.spec_from_file_location('resource_scope_v8',path)
    verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
    for name,want in result['sources'].items():
        base.require(base.sha((ROOT/name).read_bytes())==want,'resource source drift: '+name)
    binary=ROOT/SOURCE/'resource_scope_probe.exe'
    base.require(base.sha(binary.read_bytes())==result['binary_sha256'],'resource binary differs')
    raw=verifier.generated();oracle=verifier.oracle(raw)
    base.require(hashlib.sha256(raw).hexdigest()==result['fixture_sha256'] and len(raw)==result['fixture_bytes']
                 and oracle==result['oracle'],'independent ZIP oracle differs')
    records=[record(SOURCE+'/'+name,'probe') for name in ('build','compile','native')]
    native=load(SOURCE+'/native/stdout.txt');verifier.validate(native,oracle)
    outer=record(ROOT_READBACK,'root');rb=load(ROOT_READBACK+'/stdout.txt')
    base.require(rb['status']=='passed' and rb['result_sha256']==base.identity(SOURCE+'/result.json')['sha256']
                 and rb['readback_source_sha256']==base.identity('tests/fixtures/resource_scope_boundary/readback.py')['sha256']
                 and rb['negative_controls']==7 and rb['task_complete_proven'] is False,'resource readback differs')
    neg=load(NEGATIVE+'/negative.record.json')
    base.require(neg['exit_code']==0
                 and base.sha((ROOT/NEGATIVE/'negative.stdout.txt').read_bytes())==neg['stdout_sha256']
                 and base.sha((ROOT/NEGATIVE/'negative.stderr.txt').read_bytes())==neg['stderr_sha256']
                 and b'7 resource identity, coverage and error mutations rejected' in (ROOT/NEGATIVE/'negative.stdout.txt').read_bytes(),
                 'resource negative controls differ')
    return {'result':base.identity(SOURCE+'/result.json'),'readback_command':outer,
            'negative_controls':base.identity(NEGATIVE+'/negative.record.json'),
            'negative_source':base.identity('tests/fixtures/resource_scope_boundary/test_failures.py'),
            'verified_process_records':records,'source_occurrences':2,'resource_occurrences':6,
            'missing_member_fact_state':native['before']['facts'],
            'full_scope_fact_state':native['after']['facts'],
            'subset_covers_all':native['subset']['covers_all_captured_sources'],
            'scope':'synthetic stored ZIP physical order and resource evidence; distinct source and member identities',
            'limits':['resource scope is a separate axis, not a DEX relation column qualification',
                      'same-name entries require explicit physical member identity',
                      'no complete HostLab, SQL, performance or product profile qualification']}


def main():
    OUT.mkdir(parents=True,exist_ok=False)
    start=datetime.datetime.now(datetime.timezone.utc).isoformat()
    argv=[sys.executable,'-O','conformance/facts/compile_column_ledger_v7.py']
    proc=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=90)
    (OUT/'base-compiler.stdout.txt').write_bytes(proc.stdout);(OUT/'base-compiler.stderr.txt').write_bytes(proc.stderr)
    (OUT/'base-compiler.record.json').write_text(json.dumps({'argv':argv,'started_utc':start,
        'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':proc.returncode,
        'stdout_sha256':base.sha(proc.stdout),'stderr_sha256':base.sha(proc.stderr)},indent=2)+'\n',encoding='utf8')
    base.require(proc.returncode==0,'v7 recomputation failed; output retained')
    old=Path(json.loads(proc.stdout)['path'])/'column-ledger.json';report=load(old.as_posix())
    base.require(report['required_relations']==17 and report['required_columns']==156
                 and report['unassembled_projection_columns']==69 and report['task_complete_proven'] is False
                 and report['profile_admitted'] is False and report['is_task_gate'] is False
                 and all(c['full_field_qualification'] is False for c in report['columns']),'base scope differs')
    report['schema_version']='mdd.scoped-field-evidence-ledger.v8'
    report['created_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['compiler_source']=base.identity('conformance/facts/compile_column_ledger_v8.py')
    report['base_recomputation']=base.identity(old.as_posix())
    report['slices']['resource_physical_scope']=inspect_resource()
    report['global_remaining'].append('Resource member scope evidence is separate from 156 DEX columns and does not qualify compatibility mapping or a full snapshot audit.')
    report['is_task_gate']=False;report['task_complete_proven']=False;report['profile_admitted']=False
    (OUT/'column-ledger.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'relations':17,'columns':156,
                      'resource_occurrences':6,'task_complete_proven':False}))


if __name__=='__main__':main()
