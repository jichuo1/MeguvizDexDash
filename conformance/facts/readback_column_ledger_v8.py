#!/usr/bin/env python3
"""Append-only recomputation and negative controls for v8 evidence inventory."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import compile_column_ledger_v8 as audit


def run_recorded(directory,label,args):
    start=datetime.datetime.now(datetime.timezone.utc).isoformat();argv=[sys.executable,'-O',*args]
    proc=subprocess.run(argv,cwd=audit.ROOT,capture_output=True,timeout=90)
    (directory/(label+'.stdout.txt')).write_bytes(proc.stdout);(directory/(label+'.stderr.txt')).write_bytes(proc.stderr)
    (directory/(label+'.record.json')).write_text(json.dumps({'argv':argv,'started_utc':start,
        'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':proc.returncode,
        'stdout_sha256':hashlib.sha256(proc.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(proc.stderr).hexdigest()},indent=2)+'\n',encoding='utf8')
    audit.base.require(proc.returncode==0,label+' failed; output retained')
    return proc.stdout


def main():
    audit.base.require(len(sys.argv)==2,'expected one v8 ledger path')
    base=(audit.ROOT/'artifacts/mdd-026/column-ledger-v8').resolve();folder=(audit.ROOT/sys.argv[1]).resolve()
    audit.base.require(folder.is_relative_to(base) and folder!=base,'path outside v8 ledger')
    original_path=folder/'column-ledger.json';original=json.loads(original_path.read_bytes())
    now=datetime.datetime.now(datetime.timezone.utc);out=folder/'readbacks'/now.strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True,exist_ok=False)
    stdout=run_recorded(out,'recompute',['conformance/facts/compile_column_ledger_v8.py'])
    other=audit.ROOT/json.loads(stdout)['path']/'column-ledger.json';new=json.loads(other.read_bytes())
    a,b=dict(original),dict(new)
    for value in (a,b):value.pop('created_utc');value.pop('base_recomputation')
    audit.base.require(a==b,'v8 recomputation differs')
    audit.base.require(original['required_relations']==17 and original['required_columns']==len(original['columns'])==156
                       and original['unassembled_projection_columns']==69 and original['task_complete_proven'] is False
                       and original['profile_admitted'] is False and original['is_task_gate'] is False
                       and all(x['full_field_qualification'] is False for x in original['columns']),'scope/qualification differs')
    scope=original['slices']['resource_physical_scope']
    audit.base.require(scope['resource_occurrences']==6 and scope['source_occurrences']==2
                       and scope['missing_member_fact_state']=='unknown' and scope['full_scope_fact_state']=='complete'
                       and scope['subset_covers_all'] is False,'resource state differs')
    neg=run_recorded(out,'negative-controls',['conformance/facts/test_column_ledger_v8.py'])
    audit.base.require(b'9 resource-scope evidence mutations rejected' in neg,'negative controls incomplete')
    report={'status':'passed','result_sha256':audit.base.sha(original_path.read_bytes()),
            'readback_source_sha256':audit.base.sha(Path(__file__).read_bytes()),
            'recomputed_result':other.relative_to(audit.ROOT).as_posix(),
            'recomputed_sha256':audit.base.sha(other.read_bytes()),
            'relations':17,'columns':156,'resource_occurrences':6,'negative_controls':9,
            'task_complete_proven':False,'scope':'append-only evidence inventory; resource proof does not qualify DEX columns'}
    payload=(json.dumps(report)+'\n').encode('utf8')
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    (out/'stdout.txt').write_bytes(payload);(out/'stderr.txt').write_bytes(b'')
    (out/'command.json').write_text(json.dumps({'argv':[sys.executable,'-O','conformance/facts/readback_column_ledger_v8.py',sys.argv[1]],
        'started_utc':now.isoformat(),'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':0,
        'stdout_sha256':hashlib.sha256(payload).hexdigest(),'stderr_sha256':hashlib.sha256(b'').hexdigest()},indent=2)+'\n',encoding='utf8')
    sys.stdout.buffer.write(payload)


if __name__=='__main__':main()
