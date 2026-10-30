#!/usr/bin/env python3
"""Append supplemental SQLite positional, limit, CTE and compound controls."""
import json
from pathlib import Path
import sqlite3

HERE=Path(__file__).resolve().parent
CASES={
 'parenthesized_ordinal':'SELECT v,alt FROM facts ORDER BY (1),(2) DESC',
 'limit_order':'SELECT v AS alt FROM facts ORDER BY alt LIMIT 2',
 'cte_alias':'WITH s AS (SELECT v,alt FROM facts) SELECT v AS alt FROM s ORDER BY alt',
 'compound_null':'SELECT 2 AS val UNION ALL SELECT NULL AS val UNION ALL SELECT -1 AS val ORDER BY val',
}


def main():
    db=sqlite3.connect(':memory:'); records=[]
    try:
        db.execute('CREATE TABLE facts(v INTEGER,alt INTEGER NOT NULL)')
        db.executemany('INSERT INTO facts(v,alt) VALUES (?,?)',[(None,7),(2,3),(2,-9),(-1,2)])
        for name,sql in CASES.items():
            cur=db.execute(sql)
            records.append({'case':name,'sql':sql,'status':'ok','columns':[v[0] for v in cur.description],
                            'rows':[list(v) for v in cur.fetchall()]})
    finally:
        db.close()
    if len(records)!=4: raise RuntimeError('incomplete SQLite references')
    result={'status':'sqlite-reference-complete','sqlite_version':sqlite3.sqlite_version,'records':records,
            'scope':'synthetic SQLite only, no new A0/A1 or profile qualification'}
    with (HERE/'sqlite-order-extra.json').open('x',encoding='utf8',newline='\n') as f:
        json.dump(result,f,indent=2); f.write('\n')
    print(json.dumps({'status':result['status'],'sqlite_version':sqlite3.sqlite_version,'cases':4}))


if __name__=='__main__':
    main()
