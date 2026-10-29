#!/usr/bin/env python3
"""Append-only full v6 recomputation and corrupt-sibling negative controls."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import compile_column_ledger_v6 as audit


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
    audit.base.require(len(sys.argv)==2,'expected one v6 ledger path')
    base=(audit.ROOT/'artifacts/mdd-026/column-ledger-v6').resolve();folder=(audit.ROOT/sys.argv[1]).resolve()
    audit.base.require(folder.is_relative_to(base) and folder!=base,'path outside v6 ledger')
    result_path=folder/'column-ledger.json';original=json.loads(result_path.read_bytes())
    started=datetime.datetime.now(datetime.timezone.utc);append=folder/'readbacks'/started.strftime('%Y%m%dT%H%M%S%fZ')
    append.mkdir(parents=True,exist_ok=False)
    stdout=run_recorded(append,'recompute',['conformance/facts/compile_column_ledger_v6.py'])
    recomputed_dir=audit.ROOT/json.loads(stdout)['path'];recomputed=json.loads((recomputed_dir/'column-ledger.json').read_bytes())
    a,b=dict(original),dict(recomputed)
    for value in (a,b): value.pop('created_utc');value.pop('base_recomputation')
    audit.base.require(a==b,'v6 recomputation differs')
    audit.base.require(original['required_relations']==17 and original['required_columns']==len(original['columns'])==156
                       and original['unassembled_projection_columns']==69,'denominator differs')
    audit.base.require(original['is_task_gate'] is False and original['task_complete_proven'] is False
                       and original['profile_admitted'] is False and all(x['full_field_qualification'] is False for x in original['columns']),
                       'qualification overclaimed')
    counts={'method_calls':0,'method_strings':0,'method_field_accesses':0,'method_used_types':0}
    for column in original['columns']:
        relation=column['relation']
        if relation not in counts: continue
        audit.base.require(any(e['slice']=='mixed_invalid_reference_scope' for e in column['evidence']),'required evidence link missing')
        counts[relation]+=1
    audit.base.require(counts=={'method_calls':10,'method_strings':8,'method_field_accesses':12,'method_used_types':9},'link count differs')
    negative=run_recorded(append,'negative-controls',['conformance/facts/test_column_ledger_v6.py'])
    audit.base.require(b'11 corrupt-sibling evidence mutations rejected' in negative,'negative controls incomplete')
    report={'status':'passed','result_sha256':audit.base.sha(result_path.read_bytes()),
            'readback_source_sha256':audit.base.sha(Path(__file__).read_bytes()),
            'recomputed_result':(recomputed_dir/'column-ledger.json').relative_to(audit.ROOT).as_posix(),
            'recomputed_sha256':audit.base.sha((recomputed_dir/'column-ledger.json').read_bytes()),
            'relations':17,'columns':156,'reference_layer_columns':39,'negative_controls':11,'task_complete_proven':False,
            'scope':'append-only evidence inventory readback, not fact or profile qualification'}
    payload=(json.dumps(report)+'\n').encode('utf8')
    (append/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    (append/'stdout.txt').write_bytes(payload);(append/'stderr.txt').write_bytes(b'')
    (append/'command.json').write_text(json.dumps({'argv':[sys.executable,'-O','conformance/facts/readback_column_ledger_v6.py',sys.argv[1]],
        'started_utc':started.isoformat(),'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':0,
        'stdout_sha256':hashlib.sha256(payload).hexdigest(),'stderr_sha256':hashlib.sha256(b'').hexdigest()},indent=2)+'\n',encoding='utf8')
    sys.stdout.buffer.write(payload)


if __name__=='__main__':main()
