#!/usr/bin/env python3
"""Capture SQLite ORDER BY alias/input and wildcard reference on synthetic rows."""
import json
from pathlib import Path
import sqlite3

HERE=Path(__file__).resolve().parent
CASES={
 'shadow_input':'SELECT v AS alt FROM facts ORDER BY alt',
 'expression_shadow':'SELECT -v AS v FROM facts ORDER BY v',
 'duplicate_alias':'SELECT alt AS z,v AS z FROM facts ORDER BY z',
 'multiple_keys':'SELECT v AS value,alt FROM facts ORDER BY value,alt DESC',
 'wildcard_order':'SELECT * FROM facts ORDER BY v DESC,alt ASC',
 'positional':'SELECT * FROM facts ORDER BY 1,2 DESC',
 'unknown_order':'SELECT v FROM facts ORDER BY missing',
 'ordinal_out_of_range':'SELECT v FROM facts ORDER BY 3',
}


def main():
    db=sqlite3.connect(':memory:')
    records=[]
    try:
        db.execute('CREATE TABLE facts(v INTEGER,alt INTEGER NOT NULL)')
        db.executemany('INSERT INTO facts(v,alt) VALUES (?,?)',[(None,7),(2,3),(2,-9),(-1,2)])
        for name,sql in CASES.items():
            try:
                cur=db.execute(sql)
                records.append({'case':name,'sql':sql,'status':'ok','columns':[v[0] for v in cur.description],
                                'rows':[list(v) for v in cur.fetchall()]})
            except sqlite3.Error as error:
                records.append({'case':name,'sql':sql,'status':'error','error_type':type(error).__name__,
                                'message':str(error)})
    finally:
        db.close()
    if len(records)!=8 or [r['status'] for r in records].count('error')!=2:
        raise RuntimeError('unexpected SQLite control result')
    output={'status':'sqlite-reference-complete','sqlite_version':sqlite3.sqlite_version,'records':records,
            'scope':'independent SQLite synthetic rows only; no new A0/A1 run or DTO/profile qualification'}
    with (HERE/'sqlite-order-reference.json').open('x',encoding='utf8',newline='\n') as f:
        json.dump(output,f,indent=2); f.write('\n')
    print(json.dumps({'status':output['status'],'sqlite_version':sqlite3.sqlite_version,'cases':len(records)}))


if __name__=='__main__':
    main()
