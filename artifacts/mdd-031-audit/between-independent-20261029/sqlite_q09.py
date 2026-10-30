#!/usr/bin/env python3
"""Observe the exact synthetic Q09 provider rows with SQLite, including nulls."""
import json
import sqlite3


def main():
    db=sqlite3.connect(':memory:')
    db.execute('CREATE TABLE code_items(file_id INTEGER,method_idx INTEGER,insns_off INTEGER,insns_size INTEGER)')
    db.executemany('INSERT INTO code_items VALUES(?,?,?,?)',[(0,x,42,1) for x in (None,0,1,8,9,8,12)])
    queries={
        'q09_range':'SELECT method_idx,insns_off,insns_size FROM code_items WHERE file_id=0 AND method_idx BETWEEN 0 AND 8 ORDER BY method_idx',
        'q09_empty':'SELECT method_idx FROM code_items WHERE file_id=0 AND method_idx BETWEEN 20 AND 30 ORDER BY method_idx',
        'duplicates':'SELECT COUNT(*) AS n FROM code_items WHERE method_idx BETWEEN 8 AND 8',
        'null_projection':'SELECT method_idx,method_idx BETWEEN 0 AND 8 AS n FROM code_items ORDER BY method_idx',
        'not_between':'SELECT method_idx FROM code_items WHERE method_idx NOT BETWEEN 0 AND 8 ORDER BY method_idx',
        'text_bounds':"SELECT method_idx FROM code_items WHERE method_idx BETWEEN '0' AND '8' ORDER BY method_idx",
        'null_lower':'SELECT method_idx,method_idx BETWEEN NULL AND 8 AS n FROM code_items ORDER BY method_idx',
        'null_upper':'SELECT method_idx,method_idx BETWEEN 0 AND NULL AS n FROM code_items ORDER BY method_idx',
        'literal_mixed':"SELECT 1 BETWEEN '0' AND '8' AS a,1 NOT BETWEEN '0' AND '8' AS b",
    }
    results={}
    for name,sql in queries.items():
        cur=db.execute(sql)
        results[name]={'sql':sql,'columns':[column[0] for column in cur.description],'rows':cur.fetchall()}
    print(json.dumps({'sqlite_version':sqlite3.sqlite_version,'results':results,
                      'scope':'same synthetic values only; no A0/A1 or production profile'}))


if __name__=='__main__':
    main()
