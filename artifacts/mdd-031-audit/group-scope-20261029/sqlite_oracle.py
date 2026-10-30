#!/usr/bin/env python3
"""Observe SQLite grouping on the 13-row fixed metadata fixture."""
import json
import sqlite3


def main():
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE native_strings(string_idx INTEGER)')
    db.executemany('INSERT INTO native_strings VALUES (?)', [(i,) for i in range(13)])
    queries = [
        'SELECT string_idx % 2 AS parity, COUNT(*) AS n FROM native_strings GROUP BY parity ORDER BY parity',
        'SELECT string_idx % 2 AS string_idx, COUNT(*) AS n FROM native_strings GROUP BY string_idx ORDER BY string_idx',
        'SELECT string_idx % 2 AS parity, COUNT(*) AS n FROM native_strings GROUP BY parity HAVING n>6 ORDER BY parity',
        'SELECT string_idx % 2 AS parity, COUNT(*) AS n FROM native_strings GROUP BY parity HAVING COUNT(*)>6 ORDER BY parity',
        'SELECT string_idx % 2 AS parity, COUNT(*) AS n FROM native_strings GROUP BY (1) ORDER BY parity',
    ]
    print(json.dumps({'sqlite_version': sqlite3.sqlite_version, 'input_ids': list(range(13)),
                      'cases': [{'sql': q, 'rows': db.execute(q).fetchall()} for q in queries],
                      'scope': 'SQLite over same synthetic ids; no legacy profile qualification'}))


if __name__ == '__main__':
    main()
