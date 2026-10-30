#!/usr/bin/env python3
"""Bounded SQLite ASCII-only lower/upper controls; no old engine run."""
import json
from pathlib import Path
import sqlite3

HERE=Path(__file__).resolve().parent
INPUTS={'ascii':'AbC','empty':'','null':None,'nul':'A\x00a','non_ascii':'Az\u00c4\u00df'}


def main():
    db=sqlite3.connect(':memory:');records=[]
    try:
        for name,text in INPUTS.items():
            lower,upper=db.execute('SELECT lower(?),upper(?)',(text,text)).fetchone()
            records.append({'case':name,'input':text,'lower':lower,'upper':upper})
    finally:db.close()
    if len(records)!=5:raise RuntimeError('SQLite reference incomplete')
    out={'status':'sqlite-reference-complete','sqlite_version':sqlite3.sqlite_version,'records':records,
         'limits':['isolated UTF-16 surrogates cannot be bound through Python sqlite3',
                   'SQLite reference does not prove A0/A1 lower or upper behavior'],
         'a0_a1_started':False,'profile_admitted':False}
    with (HERE/'sqlite-reference.json').open('x',encoding='utf8',newline='\n') as f:
        json.dump(out,f,indent=2,ensure_ascii=True);f.write('\n')
    print(json.dumps({'status':out['status'],'cases':len(records),'sqlite_version':sqlite3.sqlite_version}))


if __name__=='__main__':main()
