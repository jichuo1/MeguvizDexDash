#!/usr/bin/env python3
"""Read-only verification of saved final delivery confirmations and failures."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT=Path(__file__).resolve().parents[4]
HERE=Path(__file__).resolve().parent


def require(ok,why):
    if not ok:
        raise ValueError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    before=json.loads((HERE/'source-before-forge.json').read_text(encoding='utf8'))
    after=json.loads((HERE/'source-after.json').read_text(encoding='utf8'))
    require(after['all_equal_before'] and after['source_count']==61
            and after['source_before_sha256']==sha(HERE/'source-before-forge.json'),'source receipt drift')
    for path,digest in before['sha256'].items():
        require(sha(ROOT/path)==digest,'source changed: '+path)
    first=json.loads((HERE/'source-before.json').read_text(encoding='utf8'))
    second=json.loads((HERE/'source-before2.json').read_text(encoding='utf8'))
    for path in first['sha256']:
        if path.startswith('crates/') or path=='Cargo.lock':
            require(first['sha256'][path]==second['sha256'][path]==before['sha256'][path],'production identity drift')
    old_main=HERE/'src/main-before-success-order.rs'
    old_runner=HERE/'run-before-forge-replay.py'
    require(sha(old_main)==first['sha256']['artifacts/mdd-034-audit/delivery-confirmation-independent-20261029/final-20261029/src/main.rs'],'first main source')
    require(sha(old_runner)==second['sha256']['artifacts/mdd-034-audit/delivery-confirmation-independent-20261029/final-20261029/run_bounded.py'],'second runner source')
    for phase,expected in [('build',0),('probe',0),('forge',101),('forge-trusted',101),('build2',0),('probe2',0),('forge2',101),('forge-trusted2',101)]:
        p=HERE/phase; rec=json.loads((p/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==expected and not rec['timed_out'] and rec['tree_empty_verified'],phase+' terminal')
        for stream in ('stdout','stderr'):
            require(sha(p/(stream+'.txt'))==rec[stream+'_sha256'],phase+' stream')
        require(sha(p/'supervisor.json')==rec['supervisor_sha256'],phase+' supervisor')
    require('error[E0451]' in (HERE/'forge2/stderr.txt').read_text(encoding='utf8')
            and 'fields `tracker` and `consumed`' in (HERE/'forge2/stderr.txt').read_text(encoding='utf8'),'receipt forgery error differs')
    require('error[E0432]' in (HERE/'forge-trusted2/stderr.txt').read_text(encoding='utf8')
            and '#[cfg(test)]' in (HERE/'forge-trusted2/stderr.txt').read_text(encoding='utf8'),'trusted entry exposed')
    def external(path):
        return {(p['name'],p['version'],p.get('checksum')) for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source')}
    require(len(external(HERE/'Cargo.lock'))==33 and external(HERE/'Cargo.lock')<=external(ROOT/'Cargo.lock'),'lock drift')
    data=json.loads((HERE/'probe2/stdout.txt').read_text(encoding='utf8'))
    require(not data['profiles_admitted'] and len(data['records'])==16,'case denominator')
    cases={x['case']:x for x in data['records']};require(len(cases)==16,'duplicate case')
    for name,count in [('success',4),('zero',0)]:
        x=cases[name];require(x['status_before']['execution_complete'] and not x['status_before']['delivery_complete']
            and x['queued_before']==count and len(x['drain']['items'])==count and x['drain']['end']['status']=='ok',name+' before/end')
        for i,item in enumerate(x['drain']['items']):
            require(item['ack']['status']=='ok' and item['row']==[{'type':'u64','value':str(i)}],name+' row/ack')
        end=x['final']['value'];require(x['final']['status']=='ok' and end['operation_status']=='ok'
            and end['execution']['complete'] and end['response']['emitted_rows']==str(count)
            and end['response']['total_rows']==str(count) and end['response']['total_rows_exact']
            and not end['response']['truncated'] and not end['response']['more_available']
            and end['response']['next_cursor'] is None and x['status_after']['delivery_complete'],name+' terminal')
    x=cases['unread'];require(x['queued_before']==4 and not x['status_before']['delivery_complete']
        and x['receipt']['status']=='error' and x['receipt']['error']['code']=='INVALID_ARGUMENT'
        and not x['status_after']['delivery_complete'] and x['status_after']['phase']=='cancelled','unread')
    for name in ('unacked_drop','consumer_drop'):
        st=cases[name]['status'];require(not st['delivery_complete'] and st['phase']=='cancelled'
            and st['error']['code']=='CANCELLED',name)
    x=cases['partial_error'];require(len(x['drain']['items'])==2 and x['drain']['end']['error']['code']=='QUOTA_EXCEEDED'
        and x['final']['status']=='ok' and x['final']['value']['operation_status']=='error'
        and x['final']['value']['error']['code']=='QUOTA_EXCEEDED' and not x['final']['value']['execution']['complete']
        and x['final']['value']['response']['emitted_rows']=='2' and x['final']['value']['response']['truncated']
        and not x['status']['delivery_complete'],'partial error washed')
    for name,code in [('cancel','CANCELLED'),('deadline','DEADLINE_EXCEEDED'),('worker_lost','WORKER_LOST')]:
        x=cases[name];require(x['final']['status']=='error' and x['final']['error']['code']==code
            and x['status']['error']['code']==code and not x['status']['delivery_complete'],name)
    x=cases['wrong_query'];require(x['wrong']['status']=='error' and x['wrong']['error']['code']=='INVALID_ARGUMENT'
        and not x['a_before']['delivery_complete'] and not x['b_before']['delivery_complete']
        and x['a_final']['status']=='ok' and x['b_final']['status']=='ok'
        and x['a_after']['delivery_complete'] and x['b_after']['delivery_complete'],'cross-query receipt')
    x=cases['wrong_queue_same_query'];require(x['wrong']['status']=='error' and x['wrong']['error']['code']=='INVALID_ARGUMENT'
        and not x['status_before_receipt_drop']['delivery_complete'] and not x['status_after_receipt_drop']['delivery_complete'],
        'same-query different-queue receipt')
    x=cases['out_of_order_ack'];require(x['ack']['status']=='error' and x['ack']['error']['code']=='INVALID_ARGUMENT'
        and not x['status']['delivery_complete'] and x['status']['phase']=='failed','out-of-order ack')
    x=cases['missing_layer'];o=x['observation'];require(o['producer']=='pending' and not o['drain']['items']
        and o['drain']['end']['error']['code']=='INCOMPLETE_FACTS' and o['final']['status']=='ok'
        and o['final']['value']['operation_status']=='error' and o['final']['value']['error']['code']=='INCOMPLETE_FACTS'
        and o['final']['value']['coverage']['facts']=='unknown' and not x['status']['delivery_complete'],'injected missing layer')
    x=cases['cancel_before_claim'];require(x['producer']['error']['code']=='CANCELLED' and not x['drain']['items']
        and x['drain']['end']['error']['code']=='CANCELLED' and not x['status']['delivery_complete'],'pre-claim cancellation')
    x=cases['cancel_after_complete'];require(x['finished']['status']=='ok' and x['finished']['value']['operation_status']=='ok'
        and x['status_before_cancel']==x['status_after_cancel'] and x['status_after_cancel']['phase']=='completed'
        and x['status_after_cancel']['delivery_complete'],'completed terminal overwritten')
    races=cases['finish_cancel_race']['iterations'];require(len(races)==20,'race count')
    outcomes={'completed':0,'cancelled':0}
    for item in races:
        final=item['final_status']; finish=item['finish']
        if final['phase']=='completed':
            require(final['delivery_complete'] and finish['status']=='ok'
                    and finish['value']['operation_status']=='ok','completed race inconsistency')
            outcomes['completed']+=1
        elif final['phase']=='cancelled':
            require(not final['delivery_complete'] and final['error']['code']=='CANCELLED'
                    and finish['status']=='error' and finish['error']['code']=='CANCELLED','cancelled race inconsistency')
            outcomes['cancelled']+=1
        else: raise ValueError('unexpected race terminal: '+str(final))
    binary=ROOT/'artifacts/local/delivery-confirmation-final-20261029-target/debug/delivery-probe.exe'
    require(sha(binary)==after['binary_sha256'],'binary drift')
    print(json.dumps({'status':'passed-scoped','cases':16,'race_iterations':20,'race_observed':outcomes,
                      'deterministic_completed_before_cancel':True,'fake_receipt_compile_error':'E0451',
                      'trusted_entry_external_compile_error':'E0432','source_count':61,'source_before_after_equal':True,
                      'source_sha256':{k:v for k,v in before['sha256'].items() if k in ('crates/mdd-query/src/budget.rs','crates/mdd-query/src/executor.rs','crates/mdd-session/src/lib.rs','Cargo.lock')},
                      'probe_sha256':sha(HERE/'probe2/stdout.txt'),'binary_sha256':sha(binary),'profiles_admitted':False,
                      'scope':'synthetic executor and query-bound queue; production worker/wire not connected',
                      'limitations':['missing-layer and worker loss are controlled injections, not corrupted APK or actual worker process loss',
                                     'observed concurrent race winners do not exhaust possible schedules',
                                     'full paging, production transport, IPC and profile not qualified']}))


if __name__=='__main__':
    main()
