#!/usr/bin/env python3
"""Read existing A0 NULL concatenation and observe independent SQLite results."""
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT=Path(__file__).resolve().parents[3]


def require(ok,why):
    if not ok: raise ValueError(why)


def main():
    path=ROOT/'artifacts/mdd-031/a0-literals/observations.json'; raw=path.read_bytes(); data=json.loads(raw)
    require(data['process_exit_code']==0 and data['closed']['closed'],'A0 prior delivery incomplete')
    item=next(x for x in data['results'] if x['id']=='like-units-case')['result']['statements'][0]
    require(item['total_rows']==1 and not item['truncated'] and item['next_offset'] is None,'A0 page incomplete')
    old=item['rows'][0][-1]; require(old=={'type':'null','value':None},'A0 concat NULL differs')
    db=sqlite3.connect(':memory:')
    null_left=db.execute('SELECT NULL || ?',('A',)).fetchone()[0]
    null_right=db.execute('SELECT ? || NULL',('A',)).fetchone()[0]
    text_nul=db.execute('SELECT hex(? || ?)',('A\0','B')).fetchone()[0]
    text_pair=db.execute('SELECT hex(? || ?)',('😀','B')).fetchone()[0]
    bytes_type,bytes_hex=db.execute("SELECT typeof(X'00FF'||X'41'),hex(X'00FF'||X'41')").fetchone()
    require(null_left is None and null_right is None and text_nul=='410042' and text_pair=='F09F988042'
            and bytes_type=='text' and bytes_hex=='00FF41','SQLite observations differ')
    print(json.dumps({'sqlite_version':sqlite3.sqlite_version,'null_left':None,'null_right':None,
                      'nul_hex':text_nul,'pair_hex':text_pair,'blob_concat_type':bytes_type,
                      'blob_concat_hex':bytes_hex,'a0_null':old,'a0_source_sha256':hashlib.sha256(raw).hexdigest(),
                      'a1':'not_run','old_engine_started':False,'profiles_admitted':False,
                      'scope':'existing A0 NULL and independent SQLite literal semantics; no candidate/profile proof'}))


if __name__=='__main__': main()
