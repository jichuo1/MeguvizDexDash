#!/usr/bin/env python3
"""Read-only independent verification of saved substr session probe and references."""
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
REFERENCE = ROOT/'artifacts/mdd-031-audit/substr-preflight/20261028T163305482932Z'


def require(ok, why):
    if not ok:
        raise ValueError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    for directory, code in [('build',101),('build2',0),('probe',0)]:
        folder=HERE/directory
        rec=json.loads((folder/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==code and rec['tree_empty_verified'] is True and not rec['timed_out'],directory+' terminal')
        for stream in ('stdout','stderr'):
            require(sha(folder/(stream+'.txt'))==rec[stream+'_sha256'],directory+' '+stream+' drift')
        require(sha(folder/'supervisor.json')==rec['supervisor_sha256'],directory+' supervisor drift')
    require('expected `()`, found `QueryStatus`' in (HERE/'build/stderr.txt').read_text(encoding='utf8'),
            'original probe build failure differs')
    functions=ROOT/'crates/mdd-sql/src/dialects/functions.rs'
    tests=ROOT/'crates/mdd-sql/src/runtime_tests.rs'
    require(sha(functions)=='43a55a0c2d35e136e609fae32b423fbec41ea5e33caf967e4d6115e58f2d0ce7', 'functions source drift')
    require(sha(tests)=='7b2ce3d781dd6f832daba8e25c12fe381932d2d8f75120fbf820750a8f535fc1', 'tests source drift')
    with (ROOT/'Cargo.lock').open('rb') as f:
        require(hashlib.sha256(f.read()).hexdigest()=='fcf51a7765c73af5e97f4aefd238fa0020c6c303ab42c20d48fbc55d8a56c089','root lock drift')
    import tomllib
    def external(path):
        return sorted((p['name'],p['version'],p.get('checksum')) for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source'))
    require(external(ROOT/'Cargo.lock')==external(HERE/'Cargo.lock') and len(external(HERE/'Cargo.lock'))==46,'external lock differs')
    data=json.loads((HERE/'probe/stdout.txt').read_text(encoding='utf8'))
    require(data['profile_admitted'] is False and len(data['cases'])==36,'case denominator')
    by={(r['dialect'],r['case']):r for r in data['cases']}
    require(len(by)==36,'duplicate case identity')
    def cell(dialect,name):
        record=by[dialect,name]
        require(record['status']=='ok' and record['complete'] is True and record['used_after_drop']==0,name+' delivery')
        require(record['used_with_result']>0,name+' lease')
        return record['rows'][0][0]
    def units(cell):
        require(cell['type']=='text' and cell['value']['original_mutf8'] is None,'text representation')
        return cell['value']['utf16']
    for dialect in ('NativeV1','DexSql010','DexSql011'):
        expected={'ascii':[98,99,100],'negative':[100,101],'empty':[],'nul':[0,66],
                  'pair':[0xd83d] if dialect=='NativeV1' else [0xd83d,0xde00],
                  'unpaired':[0xd800],'large_success':[120]}
        for key, value in expected.items():
            require(units(cell(dialect,key))==value,dialect+' '+key+' value')
        require(cell(dialect,'null')=={'type':'null'},'native null shape')
        for key,resource in [('steps','query_steps'),('workspace','query_workspace_bytes')]:
            row=by[dialect,key]
            require(row['status']=='error' and row['error']['code']=='QUOTA_EXCEEDED'
                    and row['error']['details']['budget']==resource and not row['execution_complete']
                    and row['used_after']==0,dialect+' '+key+' terminal')
        row=by[dialect,'cancel_before']
        require(row['status']=='error' and row['error']['code']=='CANCELLED' and not row['execution_complete']
                and row['used_after']==0,dialect+' pre-cancel')
        row=by[dialect,'cancel_reserved']
        require(row['observed_reservation']>100000 and row['result']['status']=='error'
                and row['result']['error']['code']=='CANCELLED' and not row['execution_complete']
                and row['used_after']==0,dialect+' observed reservation cancel')
    ref_summary=json.loads((REFERENCE/'summary.json').read_text(encoding='utf8'))
    for r in ref_summary['records']:
        path=REFERENCE/(r['variant']+'.observations.json')
        require(sha(path)==r['observations_sha256'],'reference hash')
        ref=json.loads(path.read_text(encoding='utf8'))
        cases={c['id']:c for c in ref['cases']}
        require(len(cases)==8 and all(c['close']['body']['closed'] for c in cases.values()),'reference close')
        for source,target in [('positive','ascii'),('negative_start','negative'),('nul','nul'),('supplementary','pair'),('null','null')]:
            statement=cases[source]['statements'][0]['response']['body']['statements'][0]
            require(not statement['truncated'] and statement['next_offset'] is None and statement['total_rows']==1,'reference incomplete')
            old=statement['rows'][0][0]
            for dialect in ('DexSql010','DexSql011'):
                new=cell(dialect,target)
                if source=='null':
                    require(old=={'type':'null','value':None} and new=={'type':'null'},'null DTO boundary')
                else:
                    raw=old['value'].encode('utf-16-le','surrogatepass')
                    expected=[int.from_bytes(raw[i:i+2],'little') for i in range(0,len(raw),2)]
                    require(units(new)==expected,source+' reference mismatch')
    db=sqlite3.connect(':memory:')
    sqlite_nul=db.execute('SELECT substr(?,2,2)',('A\0B',)).fetchone()[0]
    sqlite_pair=db.execute('SELECT substr(?,2,1)',('A😀B',)).fetchone()[0]
    require(sqlite_nul=='' and sqlite_pair=='😀','SQLite observed behavior differs')
    require(units(cell('NativeV1','nul'))==[0,66] and units(cell('NativeV1','pair'))==[0xd83d],
            'native-vs-SQLite differences not retained')
    print(json.dumps({'status':'passed-scoped','cases':36,'dialects':3,'legacy_reference_comparisons':10,
        'sqlite_version':sqlite3.sqlite_version,'sqlite_nul':'empty','legacy_nul_utf16':[0,66],
        'native_pair_utf16':[0xd83d],'legacy_pair_utf16':[0xd83d,0xde00],
        'source_sha256':sha(functions),'tests_sha256':sha(tests),'probe_sha256':sha(HERE/'src/main.rs'),
        'binary_sha256':sha(ROOT/'artifacts/local/substring-independent-20261029-target/debug/mdd-substring-independent.exe'),
        'dto_null_equal':False,'profiles_admitted':False,
        'scope':'three synthetic session-bound dialects; logical offset budget; no production profile',
        'limitations':['source identities observed after build; no pre-build hash','cancellation requested after observing reservation; exact internal phase unknown',
          'argument clones, SQLite, allocator overhead, RSS and transport not covered','only five of eight saved A0/A1 cases compared in this run']}))


if __name__=='__main__':
    main()
