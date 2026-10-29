#!/usr/bin/env python3
"""Independent SQLite alias-order observation for a fixed synthetic relation."""
import json
import sqlite3


def main():
    db = sqlite3.connect(':memory:')
    db.executescript('CREATE TABLE facts(id INTEGER, value TEXT); INSERT INTO facts VALUES (1,"z"),(2,"a"),(3,"m");')
    queries = [
        'SELECT 4-id AS id FROM facts ORDER BY id',
        'SELECT 4-id AS id FROM facts ORDER BY 1',
        'SELECT id AS x,4-id AS x FROM facts ORDER BY x',
        'SELECT CASE WHEN id=2 THEN NULL ELSE 4-id END AS id FROM facts ORDER BY id',
        'SELECT 4-id AS id, id AS x FROM facts ORDER BY id, x',
    ]
    print(json.dumps({'sqlite_version': sqlite3.sqlite_version,
                      'cases': [{'sql': sql, 'rows': db.execute(sql).fetchall()} for sql in queries],
                      'scope': 'synthetic relation; no DexSQL profile qualification'}))


if __name__ == '__main__':
    main()
