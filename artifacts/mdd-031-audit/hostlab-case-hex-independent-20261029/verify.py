#!/usr/bin/env python3
"""Read-only HostLab NULL/HEX wrapper and key-budget synthetic evidence check."""
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


def decode_ascii(cell):
    require(cell['type']=='text' and cell['value']['original_mutf8'] is None,'output cell type')
    units=cell['value']['utf16']
    require(all(0<=n<128 for n in units),'wrapper must emit ASCII')
    return ''.join(chr(n) for n in units)


def main():
    before=json.loads((HERE/'source-before-final.json').read_text(encoding='utf8'))
    for path,digest in before['sha256'].items():
        require(sha(ROOT/path)==digest,'source drift '+path)
    for phase in ('build','probe'):
        folder=HERE/phase; rec=json.loads((folder/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified'],phase+' terminal')
        for stream in ('stdout','stderr'):
            require(sha(folder/(stream+'.txt'))==rec[stream+'_sha256'],phase+' '+stream+' drift')
        require(sha(folder/'supervisor.json')==rec['supervisor_sha256'],phase+' supervisor drift')
    def external(path):
        return sorted((p['name'],p['version'],p.get('checksum')) for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source'))
    require(len(external(HERE/'Cargo.lock'))==46 and external(HERE/'Cargo.lock')==external(ROOT/'Cargo.lock'),'external lock drift')
    refdir=HERE/'sqlite-reference'; rec=json.loads((refdir/'record.json').read_text(encoding='utf8'))
    require(rec['exit_code']==0 and all(sha(refdir/(s+'.txt'))==rec[s]['sha256'] for s in ('stdout','stderr')),'SQLite reference drift')
    saved=json.loads((refdir/'stdout.txt').read_text(encoding='utf8'))
    db=sqlite3.connect(':memory:')
    db.execute('CREATE TABLE sample(id INTEGER,val TEXT)')
    db.executemany('INSERT INTO sample VALUES(?,?)',[(0,None),(1,''),(2,'alpha'),(3,'A\0B'),(4,'😀'),(5,'N')])
    cur=db.execute(saved['sql']); sqlite_rows=[list(x) for x in cur.fetchall()]
    require(saved['sqlite_version']==sqlite3.sqlite_version and saved['columns']==['val'] and saved['rows']==sqlite_rows,'SQLite replay differs')
    candidate=json.loads((HERE/'probe/stdout.txt').read_text(encoding='utf8'))
    require(not candidate['profiles_admitted'] and len(candidate['records'])==15,'candidate denominator')
    by={(x['dialect'],x['case']):x for x in candidate['records']}
    require(len(by)==15,'duplicate candidate case')
    results={}
    for dialect in ('NativeV1','DexSql010','DexSql011'):
        shape=by[dialect,'shape']['output']
        require(shape['status']=='ok' and shape['result']['calculation_complete']
                and shape['result']['columns']==['id','val'] and shape['result']['rows']==[],'shape failure')
        wrapped=by[dialect,'wrapped']['output']
        require(wrapped['status']=='ok' and wrapped['result']['calculation_complete']
                and wrapped['result']['columns']==['val'],'wrapper terminal')
        vals=[decode_ascii(row[0]) for row in wrapped['result']['rows']]
        require(len(vals)==7,'wrapper occurrence count')
        expected=['N','','616C706861','410042','F09F9880','4E','EDA080'] if dialect=='NativeV1' else ['N','','616C706861','41C08042','EDA0BDEDB880','4E','EDA080']
        require(vals==expected,dialect+' wrapper mismatch')
        if dialect=='NativeV1':
            require([[x] for x in vals[:6]]==sqlite_rows,'native SQLite mismatch')
        for case in ('distinct_quota','group_quota','order_quota'):
            out=by[dialect,case]['output']
            require(out['status']=='error' and out['error']['code']=='QUOTA_EXCEEDED',dialect+' '+case+' terminal')
        results[dialect]=vals
    old=ROOT/'artifacts/mdd-031/text-projection-20261029/runs/20261028T170439632106Z'
    old_hashes={}
    for engine in ('A0','A1'):
        folder=old/(engine+'-hex'); rec=json.loads((folder/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==0 and not rec['timed_out'],'legacy failed')
        for stream in ('stdout','stderr'):
            require(sha(folder/(stream+'.txt'))==rec[stream+'_sha256'],'legacy stream drift')
        table={}
        for line in (folder/'stdout.txt').read_text(encoding='utf8').splitlines():
            if line.startswith('|'):
                parts=[x.strip() for x in line.strip('|').split('|')]
                if len(parts)==2 and parts[0] in ('31','34','35'): table[parts[0]]=parts[1]
        require(table=={'31':'C080','34':'EDA080','35':'EDA0BDEDB880'},'legacy bytes differ')
        require(results['DexSql010'][3]=='41'+table['31']+'42' and results['DexSql011'][4]==table['35']
                and results['DexSql010'][6]==table['34'],'legacy hex differs')
        old_hashes[engine]=sha(folder/'stdout.txt')
    strict_decode={}
    for name,encoded in [('legacy_nul','41C08042'),('legacy_pair','EDA0BDEDB880'),('legacy_unpaired','EDA080'),('native_nul','410042'),('native_pair','F09F9880')]:
        try:
            bytes.fromhex(encoded).decode('utf8','strict');strict_decode[name]='ok'
        except UnicodeDecodeError:
            strict_decode[name]='error'
    require(strict_decode=={'legacy_nul':'error','legacy_pair':'error','legacy_unpaired':'error','native_nul':'ok','native_pair':'ok'},'strict UTF8 decoder observation')
    host=ROOT/'conformance/corpus/hostlab/source-8782f43/native_cli.py'
    host_text=host.read_text(encoding='utf8')
    require('bytes.fromhex(cell).decode("utf-8", "strict")' in host_text,'frozen HostLab decoder differs')
    binary=ROOT/'artifacts/local/between-independent-20261029-target/debug/mdd-hostlab-case-independent.exe'
    print(json.dumps({'status':'passed-scoped','bridge_queries':15,'key_low_step_quota':9,'wrapper_rows_per_dialect':7,
                      'native_sqlite_comparable_rows':6,'old_a0_a1_preexisting_hex_rows_each':3,
                      'old_a0_a1_started':False,'legacy_strict_utf8_decode':strict_decode,
                      'frozen_hostlab_cli_sha256':sha(host),'a0_a1_stdout_sha256':old_hashes,
                      'source_before_after_equal':True,'source_sha256':before['sha256'],
                      'binary_sha256':sha(binary),'profiles_admitted':False,
                      'scope':'synthetic provider; fixed HostLab CASE/HEX shape and key low-step quotas',
                      'limitations':['plain bridge, not lifecycle/runtime budget tree','strict decoder tested directly, full HostLab not executed',
                                     'MUTF8 hex is byte evidence; lone surrogate is not valid UTF8',
                                     'SQLite copies, key workspace, allocator, RSS and transport not covered']}))


if __name__=='__main__':
    main()
