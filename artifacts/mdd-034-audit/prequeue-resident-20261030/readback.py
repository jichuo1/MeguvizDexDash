#!/usr/bin/env python3
"""Independently check a single scoped real-queue observation; no assert shortcuts."""
import hashlib,json
from pathlib import Path
R=Path(__file__).resolve().parents[3]
D=Path(__file__).resolve().parent
T=D/'runs/20261030T015214252995Z'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def need(v,msg):
 if not v:raise ValueError(msg)
a=json.loads((T/'admission.json').read_text(encoding='utf-8'))
b=json.loads((T/'probe/stdout.txt').read_text(encoding='utf-8'))
need(a['status']=='completed_observation' and a['sources_unchanged'] is True,'invalid admission')
need(a['sources_before']==a['sources_after'],'source identity changed')
for p,h in a['sources_after'].items():need(digest(R/p)==h,'current source mismatch '+p)
for stage in ('build','compile','probe'):
 need(int(a['memory_'+stage]['available_bytes'])>=3*1024**3,'resource admission')
 j=a[stage]; need(j['status']=='completed' and j['exit_code']==0 and j['tree_empty_verified'] is True and j['assigned_before_resume'] is True,'job incomplete '+stage)
 need(j['limits']['memory_commit_bytes']=='2147483648','job memory limit')
need(b['count_phase_sample']['phase']=='json_count','not counting')
one=b['per_row_logical_capacity'];limit=b['workspace_limit'];sample=b['count_phase_sample']
need(sample['queue_items']==1 and sample['workspace_accounted']==one and sample['resident_accounted']==one,'reservation sample')
need(one<=limit<2*one and b['current_row_plus_queued_capacity']==2*one,'aggregate arithmetic')
need(sample['output_charged']==b['wire_per_row'] and b['output_bytes_after_producer']==2*b['wire_per_row'],'output charging stages')
need(b['terminal']['code']=='QUOTA_EXCEEDED' and b['terminal']['details']['budget']=='query_workspace_bytes','terminal error')
need(int(b['terminal']['details']['observed'])==2*one and int(b['terminal']['details']['limit'])==limit,'terminal arithmetic')
need(b['complete_result'] is False and a['profile_admitted'] is False and a['task_complete_proven'] is False,'false qualification')
files=[T/'admission.json',T/'probe/stdout.txt',T/'probe/stderr.txt',T/'probe/supervisor.json',D/'probe.rs',D/'run_bounded.py',Path(__file__)]
out={'status':'passed_scoped_readback','checks':'source identity, 3 stage admission and Job, queue sample, capacity arithmetic, output charges, quota terminal, incomplete result',
 'files_sha256':{p.relative_to(R).as_posix():digest(p) for p in files},'scope':'synthetic process-internal queue; no RSS, transport, performance or profile qualification'}
p=D/'readback-record.json'
with p.open('x',encoding='utf-8') as f:json.dump(out,f,indent=2);f.write('\n')
print(json.dumps(out))
