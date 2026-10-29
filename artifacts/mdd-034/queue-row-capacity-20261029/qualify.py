#!/usr/bin/env python3
"""Read back actual Row-capacity tests without granting runtime/profile qualification."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parents[3]
BASE=Path('artifacts/mdd-034/queue-row-capacity-20261029')


def require(ok,message):
    if not ok:raise ValueError(message)


def identity(path):
    raw=(ROOT/path).read_bytes()
    return {'path':path.as_posix(),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def record(name,exit_code):
    path=BASE/name/'record.json';item=json.loads((ROOT/path).read_bytes())
    require(item['exit_code']==exit_code,'command exit mismatch: '+name)
    for stream in ('stdout','stderr'):
        actual=identity(BASE/name/(stream+'.txt'))
        require(actual['sha256']==item[stream]['sha256'] and actual['bytes']==item[stream]['bytes'],
                'output changed: '+name+'/'+stream)
    return identity(path)


def main():
    evidence=[record('red-sparse',101),record('green-sparse',0),record('capacity-runtime',0),
              record('held-packet',0),record('query-final',0),record('clippy-final',0)]
    red=(ROOT/BASE/'red-sparse/stdout.txt').read_text(encoding='utf8')
    require('running 1 test' in red and 'oversized live Row was admitted by tiny wire length' in red,
            'real pre-fix failure absent')
    text=(ROOT/BASE/'query-final/stdout.txt').read_text(encoding='utf8')
    counts=[int(x) for x in re.findall(r'test result: ok\. (\d+) passed; 0 failed; 0 ignored;',text)]
    require(counts==[46,3],'final query/doc tests differ')
    for test in ('queue_accounts_owned_row_capacity_separately_from_wire_length',
                 'queue_counts_owned_text_bytes_and_entity_capacities_on_real_rows',
                 'queued_row_wire_and_resident_leases_are_distinct_and_release_on_ack',
                 'queued_row_lease_stays_while_cancelled_consumer_still_holds_packet'):
        require('test executor::runtime_tests::'+test+' ... ok' in text,'missing test: '+test)
    sources=[identity(Path(p)) for p in ('crates/mdd-query/src/budget.rs','crates/mdd-query/src/executor.rs',
              'crates/mdd-query/src/executor/runtime_tests.rs','Cargo.lock')]
    report={'schema_version':'mdd.queue-row-capacity.v1','task':'MDD-034',
            'created_utc':datetime.now(timezone.utc).isoformat(),'status':'passed-scoped-row-ownership-accounting',
            'source_identity_observed_at_readback':True,'sources':sources,'evidence':evidence,
            'validation':{'query_tests':46,'compile_fail_tests':3,'strict_clippy':True,
                          'sparse_row_red_retained':True,'inner_capacity_types':['utf16','bytes','entity_strings'],
                          'hierarchy':['global','worker','session','query'],
                          'ack_and_cancel_holding_release_verified':True},
            'scope':'checked logical owned Row capacity admitted at queue handoff; wire byte count independent',
            'limits':['provider allocated or cloned Row before queue admission',
                      'transient serde encoding allocation is not reserved by this change',
                      'caller-created clones and transfer buffers require separate owner accounting',
                      'Vec allocator overhead and actual RSS are not measured or bounded here',
                      'production worker, MCP, FFI and full task/profile are not qualified'],
            'task_complete_proven':False,'profile_admitted':False}
    path=ROOT/BASE/'qualification.json'
    require(not path.exists(),'qualification file already exists; preserve previous evidence')
    path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'status':report['status'],'query_tests':46,'task_complete_proven':False}))


if __name__=='__main__':main()
