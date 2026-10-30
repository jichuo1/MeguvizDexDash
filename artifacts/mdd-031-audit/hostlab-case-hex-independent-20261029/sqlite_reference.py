#!/usr/bin/env python3
"""Observe exact HostLab CASE/HEX wrapper using ordinary SQLite rows."""
import json
import sqlite3


def main():
    db=sqlite3.connect(':memory:')
    db.execute('CREATE TABLE sample(id INTEGER, val TEXT)')
    db.executemany('INSERT INTO sample VALUES(?,?)',[(0,None),(1,''),(2,'alpha'),(3,'A\0B'),(4,'😀'),(5,'N')])
    sql="SELECT CASE WHEN val IS NULL THEN 'N' ELSE hex(CAST(val AS TEXT)) END AS val FROM (SELECT id,val FROM sample ORDER BY id) AS hostlab_rows"
    cur=db.execute(sql)
    rows=cur.fetchall()
    expected=[('N',),('',),('616C706861',),('410042',),('F09F9880',),('4E',)]
    if rows!=expected:
        raise ValueError('unexpected SQLite wrapper result')
    print(json.dumps({'sqlite_version':sqlite3.sqlite_version,'sql':sql,'columns':[c[0] for c in cur.description],
                      'rows':rows,'scope':'ordinary SQLite TEXT reference; no old engine or candidate',
                      'profile_admitted':False},ensure_ascii=False))


if __name__=='__main__':
    main()
