#!/usr/bin/env python3
"""Recheck saved HEX session runs and separately observed reference engines."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tomllib

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent


def require(ok,why):
    if not ok:
        raise ValueError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    before=json.loads((HERE/'source-before2.json').read_text(encoding='utf8'))
    for path,expected in before['sha256'].items():
        require(sha(ROOT/path)==expected,'source drift: '+path)
    first=json.loads((HERE/'source-before.json').read_text(encoding='utf8'))
    require(sha(HERE/'src/main-before.rs')==first['sha256']['artifacts/mdd-031-audit/hex-independent-20261029/src/main.rs'],
            'first probe source differs')
    require(sha(HERE/'run_bounded-before.py')==first['sha256']['artifacts/mdd-031-audit/hex-independent-20261029/run_bounded.py'],
            'first runner differs')
    for phase in ('build','probe','build2','probe2'):
        folder=HERE/phase
        rec=json.loads((folder/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified'],phase+' terminal')
        for stream in ('stdout','stderr'):
            require(sha(folder/(stream+'.txt'))==rec[stream+'_sha256'],phase+' stream drift')
        require(sha(folder/'supervisor.json')==rec['supervisor_sha256'],phase+' supervisor drift')
    def external(path):
        return sorted((p['name'],p['version'],p.get('checksum')) for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source'))
    require(external(ROOT/'Cargo.lock')==external(HERE/'Cargo.lock') and len(external(HERE/'Cargo.lock'))==46,'external lock differs')
    data=json.loads((HERE/'probe2/stdout.txt').read_text(encoding='utf8'))
    require(data['profile_admitted'] is False and len(data['cases'])==45,'probe denominator')
    cases={(r['dialect'],r['case']):r for r in data['cases']}
    require(len(cases)==45,'duplicate case')
    def text(dialect,name):
        row=cases[dialect,name]
        require(row['status']=='ok' and row['complete'] is True and row['used_after_drop']==0,'delivery '+name)
        require(row['used_with_result']>0,'result lease '+name)
        cell=row['rows'][0][0]
        require(cell['type']=='text' and cell['value']['original_mutf8'] is None,'result text representation')
        return ''.join(chr(x) for x in cell['value']['utf16'])
    for dialect in ('NativeV1','DexSql010','DexSql011'):
        old=dialect!='NativeV1'
        values={'ascii':'414243','empty':'','null':'','nul':'41C08042' if old else '410042',
                'pair':'EDA0BDEDB880' if old else 'F09F9880','unpaired':'EDA080','bytes':'00FF41',
                'cast_nul':'41C08042' if old else '410042','cast_pair':'EDA0BDEDB880' if old else 'F09F9880',
                'cast_unpaired':'EDA080','large_success':'78'*10000}
        for key,value in values.items():
            require(text(dialect,key)==value,dialect+' '+key+' value')
        for key in ('steps_text','steps_bytes'):
            row=cases[dialect,key]
            require(row['status']=='error' and row['error']['code']=='QUOTA_EXCEEDED'
                    and row['error']['details']['budget']=='query_steps' and not row['execution_complete']
                    and row['used_after']==0,dialect+' '+key+' terminal')
        row=cases[dialect,'cancel_before']
        require(row['status']=='error' and row['error']['code']=='CANCELLED' and not row['execution_complete']
                and row['used_after']==0,dialect+' pre-cancel')
        row=cases[dialect,'cancel_observed']
        require(row['observed_steps']>5000 and row['result']['status']=='error'
                and row['result']['error']['code']=='CANCELLED' and not row['execution_complete']
                and row['used_after']==0,dialect+' observed cancel')
    oldroot=ROOT/'artifacts/mdd-031/text-projection-20261029/runs/20261028T170439632106Z'
    for engine in ('A0','A1'):
        folder=oldroot/(engine+'-hex')
        rec=json.loads((folder/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==0 and not rec['timed_out'],'reference engine failed')
        for stream in ('stdout','stderr'):
            require(sha(folder/(stream+'.txt'))==rec[stream+'_sha256'],'reference stream drift')
        table={}
        for line in (folder/'stdout.txt').read_text(encoding='utf8').splitlines():
            if line.startswith('|'):
                columns=[x.strip() for x in line.strip('|').split('|')]
                if len(columns)==2 and columns[0] in ('31','34','35'):
                    table[columns[0]]=columns[1]
        require(table=={'31':'C080','34':'EDA080','35':'EDA0BDEDB880'},'legacy hex rows')
        for dialect in ('DexSql010','DexSql011'):
            require(text(dialect,'cast_unpaired')==table['34'] and text(dialect,'cast_pair')==table['35'],
                    'legacy cast hex differs')
            require(text(dialect,'cast_nul')=='41'+table['31']+'42','legacy nul encoding differs')
    db=sqlite3.connect(':memory:')
    sqlite={k:db.execute('SELECT hex(CAST(? AS TEXT))',(v,)).fetchone()[0]
            for k,v in {'ascii':'ABC','empty':'','nul':'A\0B','pair':'😀'}.items()}
    sqlite['null']=db.execute('SELECT hex(NULL)').fetchone()[0]
    require(sqlite=={'ascii':'414243','empty':'','nul':'410042','pair':'F09F9880','null':''},'SQLite observations')
    for key in ('ascii','empty','nul','pair','null'):
        require(text('NativeV1',key)==sqlite[key],'native SQLite sample differs')
    binary=ROOT/'artifacts/local/hex-independent-20261029-target/debug/mdd-hex-independent.exe'
    print(json.dumps({'status':'passed-scoped','cases':45,'dialects':3,'step_quota_cases':6,
                      'pre_cancel_cases':3,'observed_cancel_cases':3,'sqlite_version':sqlite3.sqlite_version,
                      'a0_a1_saved_hex_rows_each':3,'a0_a1_started':False,
                      'sqlite_nul':'410042','legacy_nul':'41C08042',
                      'sqlite_pair':'F09F9880','legacy_pair':'EDA0BDEDB880',
                      'unpaired_hex':'EDA080','unpaired_is_valid_standard_utf8':False,
                      'source_before_and_after_equal':True,
                      'functions_sha256':before['sha256']['crates/mdd-sql/src/dialects/functions.rs'],
                      'binary_sha256':sha(binary),'profile_admitted':False,
                      'scope':'bound synthetic sessions; per-unit and per-byte logical steps, not performance',
                      'limitations':['cancel requested after observed steps; precise internal phase unknown',
                                     'encoded/result buffers, argument clones, SQLite, allocator, RSS and transport not covered',
                                     'A0/A1 references are separate DEX-source samples, not this parameter probe',
                                     'isolated surrogate hex is byte evidence, not valid UTF-8 text']}))


if __name__=='__main__':
    main()
