#!/usr/bin/env python3
"""Observe SQLite scalar and aggregate MIN/MAX; no legacy qualification."""
import json
import sqlite3


def main():
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE facts(id INTEGER)')
    db.executemany('INSERT INTO facts VALUES (?)', [(1,), (2,), (3,)])
    queries = [
        'SELECT min(1,2),max(1,2)',
        'SELECT min(id),max(id) FROM facts',
        "SELECT min(NULL,1),max('x',NULL,'y'),min(1,'0'),max(1,'0'),min('a','B'),max('a','B')",
        'SELECT min(id,2),max(id,2) FROM facts ORDER BY id',
        "SELECT hex(min('z',X'00')),hex(max('z',X'00'))",
        "SELECT min('a' COLLATE NOCASE,'B'),max('a' COLLATE NOCASE,'B')",
        "SELECT min('a','B' COLLATE NOCASE),max('a','B' COLLATE NOCASE)",
        "SELECT min('a' COLLATE BINARY,'B' COLLATE NOCASE),max('a' COLLATE BINARY,'B' COLLATE NOCASE)",
        "WITH t AS (SELECT 'a' COLLATE NOCASE AS c) SELECT min(c,'B') FROM t",
    ]
    print(json.dumps({'sqlite_version': sqlite3.sqlite_version,
                      'cases': [{'sql': q, 'rows': db.execute(q).fetchall()} for q in queries],
                      'scope': 'SQLite only; nondefault collation not admitted by candidate bridge'}))


if __name__ == '__main__':
    main()
