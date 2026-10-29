#!/usr/bin/env python3
"""Read-only verification of the saved unconsumed queue terminal counterexample."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(ok,why):
    if not ok:
        raise ValueError(why)


def main():
    before=json.loads((HERE/'source-before.json').read_text(encoding='utf8'))
    after=json.loads((HERE/'source-after.json').read_text(encoding='utf8'))
    require(after['all_equal_before'] and before['sha256']==after['sha256'],'source identities changed during run')
    for name in ('build','probe'):
        p=HERE/name; r=json.loads((p/'record.json').read_text(encoding='utf8'))
        require(r['exit_code']==0 and not r['timed_out'] and r['tree_empty_verified'],name+' terminal')
        for stream in ('stdout','stderr'):
            require(sha(p/(stream+'.txt'))==r[stream+'_sha256'],name+' stream')
        require(sha(p/'supervisor.json')==r['supervisor_sha256'],name+' supervisor')
    def external(path):
        return {(p['name'],p['version'],p.get('checksum')) for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source')}
    require(external(HERE/'Cargo.lock')<=external(ROOT/'Cargo.lock') and len(external(HERE/'Cargo.lock'))==33,'unapproved external package')
    x=json.loads((HERE/'probe/stdout.txt').read_text(encoding='utf8'))
    t=x['terminal']; status=x['status_before_receive']; drop=x['status_after_receiver_drop']; response=t['response']
    require(x['queued_items_before_receive']==4 and x['received_rows_before_terminal']==0,'queue counterexample absent')
    require(t['operation_status']=='ok' and t['execution']['complete'] is True
            and response['emitted_rows']=='4' and response['total_rows']=='4'
            and response['total_rows_exact'] is True and response['more_available'] is False
            and response['truncated'] is False and response['next_cursor'] is None,'terminal not success')
    require(status['phase']=='completed' and status['execution_complete'] and status['delivery_complete'] and status['error'] is None,
            'lifecycle not completed')
    require(x['receive_after_terminal']['status']=='error'
            and x['receive_after_terminal']['error']['code']=='INVALID_ARGUMENT'
            and x['receive_after_terminal']['error']['stage']=='cancel.checkpoint'
            and x['receive_after_terminal']['error']['message']=='query is not active','receive error differs')
    require(drop==status,'receiver drop changed already completed terminal')
    binary=ROOT/'artifacts/local/delivery-boundary-independent-20261029-target/debug/mdd-delivery-boundary-independent.exe'
    require(sha(binary)==after['binary_sha256'],'binary drift')
    print(json.dumps({'status':'confirmed_unconsumed_queue_marked_complete','queued_before_receive':4,'received_before_terminal':0,
                      'terminal_status':t['operation_status'],'delivery_complete':status['delivery_complete'],
                      'receive_error':x['receive_after_terminal']['error']['code'],
                      'source_before_after_equal':True,'source_count':len(before['sha256']),
                      'source_before_sha256':sha(HERE/'source-before.json'),'source_after_sha256':sha(HERE/'source-after.json'),
                      'probe_stdout_sha256':sha(HERE/'probe/stdout.txt'),'binary_sha256':sha(binary),
                      'profiles_admitted':False,
                      'scope':'low-level public execute_into + bounded_channel test sink only; no production worker or wire path',
                      'limitation':'sink acknowledged enqueue; this is not proof of downstream consumer acknowledgment'}))


if __name__=='__main__':
    main()
