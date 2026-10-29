#!/usr/bin/env python3
"""Observe parenthesized, signed and real-valued SQL position semantics."""
import json
import sqlite3


def main():
    db = sqlite3.connect(':memory:')
    db.executescript('CREATE TABLE facts(id INTEGER); INSERT INTO facts VALUES(1),(2),(3)')
    queries = [
        'SELECT id%2 AS parity,COUNT(*) AS n FROM facts GROUP BY (+1) ORDER BY parity',
        'SELECT COUNT(*) AS n FROM facts GROUP BY (1.0)',
        'SELECT id FROM facts GROUP BY (-1)',
        'SELECT id FROM facts ORDER BY (-1)',
    ]
    cases = []
    for sql in queries:
        try:
            cases.append({'sql': sql, 'status': 'ok', 'rows': db.execute(sql).fetchall()})
        except sqlite3.Error as error:
            cases.append({'sql': sql, 'status': 'error', 'type': type(error).__name__, 'message': str(error)})
    print(json.dumps({'sqlite_version': sqlite3.sqlite_version, 'cases': cases,
                      'scope': 'synthetic SQLite grouping; no A0/A1 profile qualification'}))


if __name__ == '__main__':
    main()
