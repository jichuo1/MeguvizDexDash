#!/usr/bin/env python3
"""Capture GROUP BY ordinal and name-resolution behavior in SQLite only."""
import json
from pathlib import Path
import sqlite3

HERE=Path(__file__).resolve().parent
CASES={
    'plain':'SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY 1 ORDER BY g',
    'parenthesized':'SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY (1) ORDER BY g',
    'nested':'SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY (((1))) ORDER BY g',
    'expression_constant':'SELECT COUNT(*) AS n FROM facts GROUP BY (1+0)',
    'two_positions':'SELECT k+1 AS g,alt AS h,COUNT(*) AS n FROM facts GROUP BY (1),(2) ORDER BY g,h',
    'alias':'SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY g ORDER BY g',
    'alias_having':'SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY g HAVING COUNT(*)>1 ORDER BY g',
    'ordinal_having':'SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY (1) HAVING COUNT(*)>1 ORDER BY g',
    'alias_input_collision':'SELECT k+1 AS alt,COUNT(*) AS n FROM facts GROUP BY alt ORDER BY alt',
    'empty':'SELECT k+1 AS g,COUNT(*) AS n FROM facts WHERE 0 GROUP BY (1) ORDER BY g',
    'zero':'SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY (0)',
    'range':'SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY (3)',
    'aggregate_position':'SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY (2)',
    'unknown':'SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY absent',
}


def main():
    db=sqlite3.connect(':memory:'); records=[]
    try:
        db.execute('CREATE TABLE facts(k INTEGER,alt INTEGER NOT NULL)')
        db.executemany('INSERT INTO facts(k,alt) VALUES (?,?)',[(None,9),(1,10),(1,20),(2,30)])
        for name,sql in CASES.items():
            try:
                cur=db.execute(sql)
                records.append({'case':name,'sql':sql,'status':'ok','columns':[x[0] for x in cur.description],
                                'rows':[list(x) for x in cur.fetchall()]})
            except sqlite3.Error as error:
                records.append({'case':name,'sql':sql,'status':'error','error_type':type(error).__name__,
                                'message':str(error)})
    finally:
        db.close()
    if len(records)!=len(CASES): raise RuntimeError('incomplete SQLite reference')
    out={'status':'sqlite-reference-complete','sqlite_version':sqlite3.sqlite_version,'records':records,
         'scope':'SQLite synthetic table; old A0/A1 not restarted; no full SQL qualification'}
    with (HERE/'sqlite-reference.json').open('x',encoding='utf8',newline='\n') as f:
        json.dump(out,f,indent=2);f.write('\n')
    print(json.dumps({'status':out['status'],'sqlite_version':sqlite3.sqlite_version,'cases':len(records),
                      'errors':sum(x['status']=='error' for x in records)}))


if __name__=='__main__':main()
