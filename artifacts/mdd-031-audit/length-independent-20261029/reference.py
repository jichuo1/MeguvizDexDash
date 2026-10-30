#!/usr/bin/env python3
"""Observe SQLite length and read the existing fixed A0 evidence, without restarting A0."""
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT=Path(__file__).resolve().parents[3]


def require(ok, why):
    if not ok:
        raise ValueError(why)


def main():
    path=ROOT/'artifacts/mdd-031/a0-literals/observations.json'
    data=path.read_bytes()
    old=json.loads(data)
    require(old['process_exit_code']==0 and old['closed']['closed'] is True,'A0 incomplete')
    entry=next(x for x in old['results'] if x['id']=='length-and-text-bytes')
    statement=entry['result']['statements'][0]
    require(statement['total_rows']==1 and statement['next_offset'] is None and not statement['truncated'],'A0 delivery')
    cells=statement['rows'][0]
    require(cells[0]['value']=='1' and cells[1]['value']=='3','A0 observed values differ')
    db=sqlite3.connect(':memory:')
    cases={'ascii':'ABC','empty':'','nul':'A\0B','pair':'😀','null':None}
    actual={k:db.execute('SELECT length(?)',(v,)).fetchone()[0] for k,v in cases.items()}
    require(actual=={'ascii':3,'empty':0,'nul':1,'pair':1,'null':None},'SQLite actual output differs')
    print(json.dumps({'sqlite_version':sqlite3.sqlite_version,'sqlite':actual,
                      'a0_sha256':hashlib.sha256(data).hexdigest(),
                      'a0_supplementary':cells[0],'a0_nul':cells[1],
                      'a1':'not_run in this evidence','surrogate_sqlite':'not bound: Python UTF-8 rejects isolated surrogate',
                      'profile_admitted':False},ensure_ascii=False))


if __name__=='__main__':
    main()
