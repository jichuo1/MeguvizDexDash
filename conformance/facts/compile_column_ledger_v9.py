#!/usr/bin/env python3
"""Add two-generation resource proof without changing fact qualification."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import compile_column_ledger_v8 as previous

base=previous.base
ROOT=base.ROOT
STAMP=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT=ROOT/'artifacts/mdd-026/column-ledger-v9'/STAMP
SOURCE='artifacts/mdd-026/resource-generation-audit/20261029T050623250919Z'
ROOT_READBACK='artifacts/mdd-026/resource-generation-audit/root-readback-20261029'
NEGATIVE=SOURCE+'/readbacks/20261029T050655470410Z'


def load(path):return json.loads((ROOT/path).read_bytes())


def inspect_generation():
    result=load(SOURCE+'/result.json')
    base.require(result['status']=='passed-synthetic-two-generation-resource-scope'
                 and result['task_complete_proven'] is False and result['profile_admitted'] is False
                 and result['resource_occurrences']==6,'generation scope differs')
    path=ROOT/'tests/fixtures/resource_generation_boundary/verify.py'
    spec=importlib.util.spec_from_file_location('resource_generation_v9',path)
    verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
    for name,want in result['sources'].items():
        base.require(base.sha((ROOT/name).read_bytes())==want,'generation source drift: '+name)
    base.require(base.sha((ROOT/SOURCE/'resource_generation_probe.exe').read_bytes())==result['binary_sha256'],
                 'generation binary differs')
    raw_a,raw_b=verifier.generated(False),verifier.generated(True)
    a,b=verifier.oracle(raw_a),verifier.oracle(raw_b)
    base.require(hashlib.sha256(raw_a).hexdigest()==result['generation_a_sha256']
                 and hashlib.sha256(raw_b).hexdigest()==result['generation_b_sha256']
                 and a==result['oracle_a'] and b==result['oracle_b'],'generation byte oracle differs')
    records=[previous.record(SOURCE+'/'+name,'probe') for name in ('build','compile','native')]
    native=load(SOURCE+'/native/stdout.txt');verifier.validate(native,a,b,raw_a,raw_b)
    outer=previous.record(ROOT_READBACK,'root');rb=load(ROOT_READBACK+'/stdout.txt')
    base.require(rb['status']=='passed' and rb['result_sha256']==base.identity(SOURCE+'/result.json')['sha256']
                 and rb['readback_source_sha256']==base.identity('tests/fixtures/resource_generation_boundary/readback.py')['sha256']
                 and rb['negative_controls']==9 and rb['task_complete_proven'] is False,'generation readback differs')
    neg=load(NEGATIVE+'/negative.record.json')
    base.require(neg['exit_code']==0
                 and base.sha((ROOT/NEGATIVE/'negative.stdout.txt').read_bytes())==neg['stdout_sha256']
                 and base.sha((ROOT/NEGATIVE/'negative.stderr.txt').read_bytes())==neg['stderr_sha256']
                 and b'9 cross-generation identity, bytes, coverage and error mutations rejected' in (ROOT/NEGATIVE/'negative.stdout.txt').read_bytes(),
                 'generation negative controls differ')
    return {'result':base.identity(SOURCE+'/result.json'),'readback_command':outer,
            'negative_controls':base.identity(NEGATIVE+'/negative.record.json'),
            'negative_source':base.identity('tests/fixtures/resource_generation_boundary/test_failures.py'),
            'verified_process_records':records,'generations':2,'resource_occurrences':6,
            'old_missing_after_foreign':native['a_rejected']['facts'],
            'new_missing_after_foreign':native['b_rejected']['facts'],
            'foreign_a_error':native['foreign_a']['code'],'foreign_b_error':native['foreign_b']['code'],
            'disk_rewritten_between_captures':native['disk_rewritten_between_captures'],
            'scope':'actual rewrite of one synthetic APK between captures; byte-oracle and resource coverage only',
            'limits':['resource evidence cannot prove cross-generation SQL, Smali, pagination or all DEX facts',
                      'no complete HostLab, SQL, performance or product profile qualification']}


def main():
    OUT.mkdir(parents=True,exist_ok=False)
    start=datetime.datetime.now(datetime.timezone.utc).isoformat()
    argv=[sys.executable,'-O','conformance/facts/compile_column_ledger_v8.py']
    proc=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=90)
    (OUT/'base-compiler.stdout.txt').write_bytes(proc.stdout);(OUT/'base-compiler.stderr.txt').write_bytes(proc.stderr)
    (OUT/'base-compiler.record.json').write_text(json.dumps({'argv':argv,'started_utc':start,
        'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':proc.returncode,
        'stdout_sha256':base.sha(proc.stdout),'stderr_sha256':base.sha(proc.stderr)},indent=2)+'\n',encoding='utf8')
    base.require(proc.returncode==0,'v8 recomputation failed; output retained')
    old=Path(json.loads(proc.stdout)['path'])/'column-ledger.json';report=load(old.as_posix())
    base.require(report['required_relations']==17 and report['required_columns']==156
                 and report['unassembled_projection_columns']==69 and report['task_complete_proven'] is False
                 and report['profile_admitted'] is False and report['is_task_gate'] is False
                 and all(c['full_field_qualification'] is False for c in report['columns']),'base scope differs')
    report['schema_version']='mdd.scoped-field-evidence-ledger.v9'
    report['created_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['compiler_source']=base.identity('conformance/facts/compile_column_ledger_v9.py')
    report['base_recomputation']=base.identity(old.as_posix())
    report['slices']['resource_generation_scope']=inspect_generation()
    report['global_remaining'].append('Two-generation resource proof does not establish cross-generation SQL, Smali, pagination or complete DEX facts.')
    report['is_task_gate']=False;report['task_complete_proven']=False;report['profile_admitted']=False
    (OUT/'column-ledger.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'relations':17,'columns':156,
                      'resource_generations':2,'task_complete_proven':False}))


if __name__=='__main__':main()
