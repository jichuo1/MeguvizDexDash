#!/usr/bin/env python3
"""Observe Q09-like inclusive ranges and nulls in actual SQLite only."""
import json
import sqlite3


def main():
    db=sqlite3.connect(':memory:')
    db.execute('CREATE TABLE sample(method_idx INTEGER)')
    db.executemany('INSERT INTO sample(method_idx) VALUES(?)',[(x,) for x in (None,-1,0,1,8,9,8)])
    queries={
        'q09_range':'SELECT method_idx FROM sample WHERE method_idx BETWEEN 0 AND 8 ORDER BY method_idx',
        'q09_negative_range':'SELECT method_idx FROM sample WHERE method_idx BETWEEN -1 AND 1 ORDER BY method_idx',
        'duplicates':'SELECT COUNT(*) FROM sample WHERE method_idx BETWEEN 8 AND 8',
        'null_projection':'SELECT method_idx,method_idx BETWEEN 0 AND 8 FROM sample ORDER BY method_idx',
        'not_between':'SELECT method_idx FROM sample WHERE method_idx NOT BETWEEN 0 AND 8 ORDER BY method_idx',
        'text_bounds':"SELECT method_idx FROM sample WHERE method_idx BETWEEN '0' AND '8' ORDER BY method_idx",
        'null_lower':'SELECT method_idx,method_idx BETWEEN NULL AND 8 FROM sample ORDER BY method_idx',
        'null_upper':'SELECT method_idx,method_idx BETWEEN 0 AND NULL FROM sample ORDER BY method_idx',
        'literal_mixed':"SELECT 1 BETWEEN '0' AND '8', 1 NOT BETWEEN '0' AND '8'",
    }
    result={}
    for name,sql in queries.items():
        cur=db.execute(sql)
        result[name]={'sql':sql,'columns':[x[0] for x in cur.description],'rows':cur.fetchall()}
    print(json.dumps({'sqlite_version':sqlite3.sqlite_version,'samples':result,
                      'reference_scope':'SQLite only; A0/A1 not executed; no profile qualification'},ensure_ascii=False))


if __name__=='__main__':
    main()
