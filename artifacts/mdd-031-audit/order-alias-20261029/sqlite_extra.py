#!/usr/bin/env python3
"""Independent wildcard/NULL ordering observation on fixed synthetic values."""
import json
import sqlite3


def main():
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE facts(id INTEGER, value TEXT)')
    db.executemany('INSERT INTO facts VALUES (?,?)', [(1, 'a\0b'), (2, 'a\0b'), (3, 'a\0b')])
    queries = [
        'SELECT *,4-id AS id FROM facts ORDER BY id',
        'SELECT 4-id AS id,* FROM facts ORDER BY id',
        'SELECT CASE WHEN id=2 THEN NULL ELSE 4-id END AS id FROM facts ORDER BY id DESC NULLS LAST',
    ]
    print(json.dumps({'sqlite_version': sqlite3.sqlite_version,
                      'cases': [{'sql': sql, 'rows': db.execute(sql).fetchall()} for sql in queries],
                      'scope': 'synthetic relation; not legacy dialect qualification'}))


if __name__ == '__main__':
    main()
