#!/usr/bin/env python3
"""Read-only validation of isolated source identity, key leases and ToSql evidence."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
SNAP=ROOT/'handoff/key-lease-cebb3a7-20261029'


def require(ok,why):
    if not ok:
        raise ValueError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    before=json.loads((HERE/'snapshot-before.json').read_text(encoding='utf8'))
    pbefore=json.loads((HERE/'probe-before.json').read_text(encoding='utf8'))
    after=json.loads((HERE/'snapshot-after.json').read_text(encoding='utf8'))
    require(before['base_commit']=='cebb3a759e3131287c53b75a2eab349bba77ee5f'
            and len(before['files_sha256'])==91 and len(before['override_sources'])==3,'snapshot identity')
    require(after['all_snapshot_files_equal'] and after['all_probe_files_equal']
            and after['snapshot_before_sha256']==sha(HERE/'snapshot-before.json')
            and after['probe_before_sha256']==sha(HERE/'probe-before.json'),'before/after receipt')
    for name,digest in before['files_sha256'].items():
        require(sha(SNAP/name)==digest,'snapshot drift: '+name)
    for name,digest in pbefore['probe_files_sha256'].items():
        require(sha(HERE/name)==digest,'probe drift: '+name)
    require(sha(HERE/'run_tosql2.py')==after['tosql_runner_sha256'],'corrected runner drift')
    for name in ('build','probe','tosql','tosql2'):
        p=HERE/name; rec=json.loads((p/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified'],name+' terminal')
        for stream in ('stdout','stderr'):
            require(sha(p/(stream+'.txt'))==rec[stream+'_sha256'],name+' stream')
        require(sha(p/'supervisor.json')==rec['supervisor_sha256'],name+' supervisor')
    old=(HERE/'tosql/stdout.txt').read_text(encoding='utf8')
    good=(HERE/'tosql2/stdout.txt').read_text(encoding='utf8')
    require('running 0 tests' in old and '0 passed' in old,'zero-test failure not retained')
    require('running 1 test' in good and 'key_lease_survives_actual_rusqlite_to_sql_callback ... ok' in good
            and '1 passed; 0 failed; 0 ignored' in good,'ToSql callback test not run')
    def external(path):
        return {(p['name'],p['version'],p.get('checksum')) for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source')}
    require(len(external(HERE/'Cargo.lock'))==46 and external(HERE/'Cargo.lock')==external(SNAP/'Cargo.lock'),'external lock differs')
    data=json.loads((HERE/'probe/stdout.txt').read_text(encoding='utf8'))
    require(not data['profile_admitted'] and len(data['records'])==48,'case denominator')
    by={(r['dialect'],r['case']):r for r in data['records']}
    require(len(by)==48,'duplicate case')
    for d in ('NativeV1','DexSql010','DexSql011'):
        for typ in ('text','bytes'):
            for op in ('distinct','group','order'):
                low=by[d,f'{typ}_{op}_low']
                require(low['status']=='error' and low['error']['code']=='QUOTA_EXCEEDED'
                        and low['error']['details']['budget']=='query_workspace_bytes'
                        and not low['execution_complete'] and low['used_after']==0,d+' low '+typ+' '+op)
                high=by[d,f'{typ}_{op}_high']
                require(high['status']=='ok' and high['complete'] and high['used_with_result']>0
                        and high['used_after_drop']==0,d+' high terminal')
                values=[[int(x['value']) for x in row] for row in high['rows']]
                expected={'distinct':[[2]],'group':[[1],[1]],'order':[[1],[0]]}[op]
                require(values==expected,d+' high result '+op)
            pre=by[d,f'{typ}_order_cancel_before']
            require(pre['status']=='error' and pre['error']['code']=='CANCELLED'
                    and not pre['execution_complete'] and pre['used_after']==0,'pre cancel')
            observed=by[d,f'{typ}_order_cancel_observed']
            require(observed['observed_workspace']>100000 and observed['outcome']['status']=='error'
                    and observed['outcome']['error']['code']=='CANCELLED'
                    and not observed['execution_complete'] and observed['used_after']==0,'observed cancel')
    binary=ROOT/'artifacts/local/key-lease-independent-20261029-target/debug/mdd-key-lease-independent.exe'
    require(sha(binary)==after['binary_sha256'],'binary drift')
    print(json.dumps({'status':'passed-scoped','base_commit':before['base_commit'],'snapshot_sources':91,
                      'overrides':before['override_sources'],'cases':48,'low_quota_cases':18,
                      'complete_success_cases':18,'pre_cancel_cases':6,'observed_cancel_cases':6,
                      'tosql_actual_tests_passed':1,'first_tosql_filter_ran_zero_tests':True,
                      'binary_sha256':sha(binary),'source_before_after_equal':True,'profiles_admitted':False,
                      'scope':'isolated committed snapshot plus exactly three frozen SQL files; synthetic bound sessions',
                      'limitations':['ToSql test instruments actual callback, not SQLite copy accounting',
                                     'SQLite transient copy and sorter, provider/argument copies, allocator and RSS not covered',
                                     'cancel after observed workspace; precise internal instruction unknown',
                                     'production worker, transport and HostLab profile not qualified']}))


if __name__=='__main__':
    main()
