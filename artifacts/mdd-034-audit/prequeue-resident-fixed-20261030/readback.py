#!/usr/bin/env python3
"""Compare scoped red/green observations, runtime provenance, and terminal behavior."""
import hashlib,json
from pathlib import Path
R=Path(__file__).resolve().parents[3];D=Path(__file__).resolve().parent
OLD=R/'artifacts/mdd-034-audit/prequeue-resident-20261030/runs/20261030T015214252995Z'
NEW=D/'runs/20261030T015618057401Z'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def need(v,msg):
 if not v:raise ValueError(msg)
a=json.loads((OLD/'admission.json').read_text(encoding='utf-8')); b=json.loads((NEW/'admission.json').read_text(encoding='utf-8'))
x=json.loads((OLD/'probe/stdout.txt').read_text(encoding='utf-8'));y=json.loads((NEW/'probe/stdout.txt').read_text(encoding='utf-8'))
for label,j in [('old',a),('new',b)]:
 need(j['status']=='completed_observation' and j['sources_unchanged'] and j['sources_before']==j['sources_after'],label+' sources')
 for stage in ('build','compile','probe'):
  s=j[stage];need(int(j['memory_'+stage]['available_bytes'])>=3*1024**3,label+' admission')
  need(s['status']=='completed' and s['exit_code']==0 and s['tree_empty_verified'] and s['assigned_before_resume'],label+' job '+stage)
  need(s['limits']['memory_commit_bytes']=='2147483648',label+' Job limit')
  
 exe=Path(j['probe']['command_argv'][0]);need(exe.is_file() and sha(exe)==j['binary_sha256'],label+' binary identity')
 need(not j['profile_admitted'] and not j['task_complete_proven'],label+' qualification')
need(a['binary_sha256']!=b['binary_sha256'],'distinct binaries')
need(a['sources_after']['Cargo.lock']==b['sources_after']['Cargo.lock'],'lock changed')
for path in ('crates/mdd-query/src/executor.rs','crates/mdd-query/src/budget.rs'):
 need(a['sources_after'][path]!=b['sources_after'][path] and sha(R/path)==b['sources_after'][path],'red/green code identity '+path)
for path,h in b['sources_after'].items():need(sha(R/path)==h,'new source changed '+path)
need(x['per_row_logical_capacity']==y['per_row_logical_capacity']==3989 and x['workspace_limit']==y['workspace_limit']==5983,'scenario differs')
need(x['count_phase_sample']['queue_items']==1 and x['count_phase_sample']['workspace_accounted']==3989 and x['current_row_plus_queued_capacity']==7978,'red phase')
need(x['output_bytes_after_producer']==854 and y['output_bytes_after_producer']==y['wire_per_row']==427,'wire charges')
need(y['phase_samples'][0]['workspace_accounted']==3989 and y['phase_samples'][0]['resident_accounted']==3989 and y['phase_samples'][0]['queue_items']==0,'first row not reserved')
need(y['second_row_json_count_steps']==0 and y['queue_items_before_receive']==1,'second row count or queued items')
need(y['first_row_consumed_and_acknowledged'] and y['workspace_after_ack']==0,'first row delivery')
for v in (x,y):
 need(v['terminal']['code']=='QUOTA_EXCEEDED' and v['terminal']['details']['budget']=='query_workspace_bytes' and v['complete_result'] is False,'terminal')
 need(int(v['terminal']['details']['limit'])==5983 and int(v['terminal']['details']['observed'])==7978,'terminal bounds')
files=[OLD/'admission.json',OLD/'probe/stdout.txt',NEW/'admission.json',NEW/'probe/stdout.txt',NEW/'probe/stderr.txt',NEW/'probe/supervisor.json',D/'probe.rs',D/'run_bounded.py',Path(__file__)]
out={'status':'passed_scoped_readback','old_binary_sha256':a['binary_sha256'],'new_binary_sha256':b['binary_sha256'],
'old_executor_sha256':a['sources_after']['crates/mdd-query/src/executor.rs'],'new_executor_sha256':b['sources_after']['crates/mdd-query/src/executor.rs'],
'old_budget_sha256':a['sources_after']['crates/mdd-query/src/budget.rs'],'new_budget_sha256':b['sources_after']['crates/mdd-query/src/budget.rs'],
'files_sha256':{p.relative_to(R).as_posix():sha(p) for p in files},'scope':'synthetic process-internal queue; no RSS, transport, performance or profile qualification'}
with (D/'readback-record.json').open('x',encoding='utf-8') as f:json.dump(out,f,indent=2);f.write('\n')
print(json.dumps(out))
