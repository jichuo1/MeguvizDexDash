#!/usr/bin/env python3
"""Read back real allocation observations and fixed-serde_json regression logs."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[3]
BASE=Path('artifacts/mdd-034/streaming-json-20261029')


def require(ok,message):
    if not ok:raise ValueError(message)


def identity(path):
    raw=(ROOT/path).read_bytes()
    return {'path':path.as_posix(),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def record(name,expected):
    path=BASE/name/'record.json';rec=json.loads((ROOT/path).read_bytes())
    require(rec['exit_code']==expected,'command exit differs: '+name)
    for stream in ('stdout','stderr'):
        actual=identity(BASE/name/(stream+'.txt'))
        require(actual['bytes']==rec[stream]['bytes'] and actual['sha256']==rec[stream]['sha256'],
                'command stream changed: '+name+'/'+stream)
    return identity(path)


def main():
    checks=[record(name,0) for name in ['red2-build','red2-compile','red2-run','green-final-build',
            'green-final-compile','green-final-run','json-tests-first','parity-first','boundary-tests-2',
            'precheck-test','query-tests-final','clippy-final']]
    failed=record('boundary-tests',101)
    error=(ROOT/BASE/'boundary-tests/stderr.txt').read_text(encoding='utf8')
    require('expected function, found `ResultEnvelope`' in error,'initial test compile failure differs')
    red=json.loads((ROOT/BASE/'red2-run/stdout.txt').read_bytes())
    green=json.loads((ROOT/BASE/'green-final-run/stdout.txt').read_bytes())
    observations=[]
    for name,budget in [('small_output','output_bytes'),('small_workspace','query_workspace_bytes')]:
        a,b=red[name],green[name]
        require(a['output_limit']==b['output_limit'] and a['workspace_limit']==b['workspace_limit'],
                'probe budget changed: '+name)
        for value in (a,b):
            require(value['queue_error']['code']=='QUOTA_EXCEEDED' and value['queue_error']['details']['budget']==budget
                    and value['terminal']['response']['truncated'] is True and value['terminal']['execution']['complete'] is False,
                    'real error/terminal differs: '+name)
        require(a['max_single_allocation_request']>=262144 and b['max_single_allocation_request']<65536,
                'allocation request observation differs: '+name)
        observations.append({'case':name,'budget':budget,'red_max_single_request':a['max_single_allocation_request'],
                             'green_max_single_request':b['max_single_allocation_request']})
    details=green['small_output']['queue_error']['details']
    require(details['encoded_length_exact'] is False and int(details['attempted_prefix_bytes'])>64,
            'partial byte count was mislabeled exact')
    text=(ROOT/BASE/'query-tests-final/stdout.txt').read_text(encoding='utf8')
    counts=[int(x) for x in re.findall(r'test result: ok\. (\d+) passed; 0 failed; 0 ignored;',text)]
    require(counts==[52,3],'query/doc test counts differ')
    for test in ['streaming_row_json_matches_fixed_serde_json_for_all_value_shapes',
                 'json_count_preserves_real_error_and_checked_overflow',
                 'json_count_rechecks_released_parent_budget_and_final_charge_is_atomic',
                 'json_count_cancel_preserves_terminal_and_no_output_charge',
                 'low_output_fails_on_observed_prefix_and_exact_limit_delivers',
                 'oversized_owned_row_is_rejected_before_json_counting']:
        require('test executor::runtime_tests::'+test+' ... ok' in text,'test not run: '+test)
    sources=[identity(Path(p)) for p in ['crates/mdd-query/src/budget.rs','crates/mdd-query/src/executor.rs',
             'crates/mdd-query/src/executor/runtime_tests.rs','crates/mdd-query/src/ir/mod.rs','Cargo.lock',
             'artifacts/mdd-034/streaming-json-20261029/probe.rs']]
    report={'schema_version':'mdd.streaming-json-count.v1','task':'MDD-034',
            'created_utc':datetime.now(timezone.utc).isoformat(),'status':'passed-scoped-fixed-serde-json-count',
            'source_identity_observed_at_readback':True,'sources':sources,'evidence':checks,
            'retained_initial_test_compile_failure':failed,'pre_change_identity':identity(BASE/'red-identity.json'),
            'allocation_observations':observations,'query_tests':52,'compile_fail_tests':3,'strict_clippy':True,
            'scope':'fixed serde_json writer for query queue counting; exact count is atomically charged after successful traversal',
            'limits':['allocation observation is largest individual request in one process, not RSS or performance',
                      'source Row and values were created before measurement and before queue admission',
                      'public Bytes serializer and other serializers remain outside this streaming guarantee',
                      'non-Bytes temporary values, consumer copies, transport and allocator overhead are not fully bounded',
                      'producer worker/MCP/FFI and full task/profile remain unqualified'],
            'task_complete_proven':False,'profile_admitted':False}
    path=ROOT/BASE/'qualification.json';require(not path.exists(),'preserve prior qualification')
    path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'status':report['status'],'cases':len(observations),'task_complete_proven':False}))


if __name__=='__main__':main()
