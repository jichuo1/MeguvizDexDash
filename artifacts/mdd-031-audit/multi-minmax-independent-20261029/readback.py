#!/usr/bin/env python3
"""Recompute SQLite reference in memory and read saved candidate results."""
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
EXPLICIT={'nocase_left','nocase_right','binary_then_nocase','nocase_then_binary',
          'reversed_collations','column_explicit'}
COLUMNS={'column_binding','column_null','column_multirow'}


def require(ok,why):
    if not ok:raise RuntimeError(why)


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def read(p):return json.loads(p.read_text(encoding='utf8'))


def sqlite_cell(v):
    if v is None:return {'type':'null','value':None}
    if isinstance(v,int):return {'type':'integer','value':str(v)}
    if isinstance(v,float):return {'type':'real','f64_be_hex':struct.pack('>d',v).hex()}
    if isinstance(v,str):return {'type':'text','value':v}
    if isinstance(v,bytes):return {'type':'blob','hex':v.hex()}
    raise TypeError('unexpected SQLite cell')


def unwrap_sqlite(v):
    if v['type']=='null':return None
    if v['type']=='integer':return int(v['value'])
    if v['type']=='text':return v['value']
    if v['type']=='blob':return bytes.fromhex(v['hex'])
    raise RuntimeError('unexpected SQLite stored type')


def unwrap_candidate(v):
    if v['type']=='null':
        require('value' not in v,'candidate NULL changed');return None
    if v['type'] in ('i64','u64'):return int(v['value'])
    if v['type']=='bytes':return bytes(v['value'])
    if v['type']=='text':
        raw=b''.join(int(unit).to_bytes(2,'little') for unit in v['value']['utf16'])
        return raw.decode('utf-16-le',errors='strict')
    raise RuntimeError('unexpected candidate cell')


def database(nocase):
    db=sqlite3.connect(':memory:')
    sql=('CREATE TABLE facts(id INTEGER PRIMARY KEY,c TEXT COLLATE NOCASE,d TEXT COLLATE BINARY,v INTEGER)'
         if nocase else 'CREATE TABLE facts(id INTEGER PRIMARY KEY,c TEXT,d TEXT,v INTEGER)')
    db.execute(sql);db.executemany('INSERT INTO facts VALUES (?,?,?,?)',[(1,'a','B',2),(2,'a','B',None),(3,'z','A',1)])
    return db


def main():
    q=read(HERE/'qualification.json');rec=read(HERE/'verify-run/record.json')
    require(q['status']=='passed-supported-subset' and rec['exit_code']==0 and not q['profile_admitted']
            and not q['dto_equivalent'] and not q['a0_a1_started'],'scope or terminal changed')
    for stream in ('stdout','stderr'):
        require(sha(HERE/('verify-run/'+stream+'.txt'))==rec[stream]['sha256'],'verifier stream changed')
    for p,digest in q['source_sha256'].items():require(sha(ROOT/p)==digest,'tested source changed: '+p)
    require(sha(HERE/'sqlite-reference.json')==q['sqlite_reference_sha256']
            and sha(HERE/'sqlite-binary-columns.json')==q['sqlite_binary_sha256']
            and sha(HERE/'probe/stdout.txt')==q['candidate_stdout_sha256'],'raw reference changed')
    binary=ROOT/'artifacts/local/like-independent-20261029-target/debug/mdd-multi-minmax-independent.exe'
    require(sha(binary)==q['binary_sha256'],'candidate binary changed')
    reference=read(HERE/'sqlite-reference.json');binary_ref=read(HERE/'sqlite-binary-columns.json')
    require(reference['sqlite_version']==binary_ref['sqlite_version']==sqlite3.sqlite_version,'SQLite version differs')
    refs={x['case']:x for x in reference['records']};binary_refs={x['case']:x for x in binary_ref['records']}
    data=read(HERE/'probe/stdout.txt');rows={(x['dialect'],x['case']):x for x in data['records']}
    require(len(refs)==23 and len(binary_refs)==4 and len(rows)==len(data['records'])==69
            and not data['profile_admitted'],'denominator differs')
    db=database(True)
    try:
        for name,ref in refs.items():
            try:
                cur=db.execute(ref['sql']);got={'status':'ok','columns':[x[0] for x in cur.description],
                                              'rows':[[sqlite_cell(x) for x in row] for row in cur.fetchall()]}
            except sqlite3.Error as error:got={'status':'error','message':str(error)}
            require(got['status']==ref['status'],'SQLite status changed: '+name)
            if ref['status']=='ok':require(got['columns']==ref['columns'] and got['rows']==ref['rows'],'SQLite rows changed: '+name)
            else:require(got['message']==ref['message'],'SQLite error changed: '+name)
    finally:db.close()
    db=database(False)
    try:
        for name,ref in binary_refs.items():
            cur=db.execute(ref['sql']);cols=[x[0] for x in cur.description];raw=[list(x) for x in cur.fetchall()]
            require(cols==ref['columns'] and raw==ref['rows'],'BINARY reference changed: '+name)
    finally:db.close()
    counts={'value_matches':0,'invalid_arity':0,'explicit_collation_unsupported':0}
    for dialect in ('native','010','011'):
        for name,ref in refs.items():
            item=rows[(dialect,name)];result=item['result'];require(item['sql']==ref['sql'],'SQL changed')
            if name in EXPLICIT:
                require(result['status']=='error' and result['error']['code']=='UNSUPPORTED_QUERY','collation error changed')
                counts['explicit_collation_unsupported']+=1;continue
            if ref['status']=='error':
                require(result['status']=='error' and result['error']['code']=='INVALID_ARGUMENT','arity error changed')
                counts['invalid_arity']+=1;continue
            require(result['status']=='ok' and result['result']['calculation_complete'],'candidate terminal changed')
            expected=(binary_refs[name]['rows'] if name in COLUMNS else [[unwrap_sqlite(c) for c in row] for row in ref['rows']])
            require([[unwrap_candidate(c) for c in row] for row in result['result']['rows']]==expected,'candidate value changed')
            counts['value_matches']+=1
    require(counts=={k:q[k] for k in counts},'count changed')
    print(json.dumps({'status':'passed-readback-only',**counts,'sqlite_version':sqlite3.sqlite_version,
                      'a0_a1_started':False,'dto_equivalent':False,'profile_admitted':False,
                      'scope':'SQLite in-memory recomputation and synthetic provider; explicit collation remains unsupported'}))


if __name__=='__main__':main()
