#!/usr/bin/env python3
"""Capture column baselines without declaring unavailable NOCASE metadata."""
import json
from pathlib import Path
import sqlite3

HERE=Path(__file__).resolve().parent


def main():
    reference=json.loads((HERE/'sqlite-reference.json').read_text(encoding='utf8'))
    selected={'column_binding','column_explicit','column_null','column_multirow'}
    db=sqlite3.connect(':memory:');records=[]
    try:
        db.execute('CREATE TABLE facts(id INTEGER PRIMARY KEY,c TEXT,d TEXT,v INTEGER)')
        db.executemany('INSERT INTO facts VALUES (?,?,?,?)',[(1,'a','B',2),(2,'a','B',None),(3,'z','A',1)])
        for case in reference['records']:
            if case['case'] not in selected:continue
            cur=db.execute(case['sql'])
            records.append({'case':case['case'],'sql':case['sql'],'columns':[x[0] for x in cur.description],
                            'rows':[list(x) for x in cur.fetchall()]})
    finally:db.close()
    if len(records)!=4:raise RuntimeError('incomplete binary-column reference')
    out={'sqlite_version':sqlite3.sqlite_version,'records':records,
         'scope':'ordinary TEXT columns with default BINARY; not a proof of SQLite virtual-table collation behavior'}
    with (HERE/'sqlite-binary-columns.json').open('x',encoding='utf8',newline='\n') as f:
        json.dump(out,f,indent=2);f.write('\n')
    print(json.dumps({'status':'sqlite-binary-columns-complete','cases':len(records),'sqlite_version':sqlite3.sqlite_version}))


if __name__=='__main__':main()
