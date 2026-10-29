#!/usr/bin/env python3
"""Record actual SQLite handling of positional 32-bit magnitude boundaries."""
import json
import sqlite3


def main():
    db = sqlite3.connect(':memory:')
    db.executescript('CREATE TABLE facts(id INTEGER); INSERT INTO facts VALUES(1),(2),(3)')
    queries = ['SELECT COUNT(*) FROM facts GROUP BY ' + x for x in
               ('2147483647', '2147483648', '-2147483647', '-2147483648', '1.0')]
    cases = []
    for sql in queries:
        try:
            cases.append({'sql': sql, 'status': 'ok', 'rows': db.execute(sql).fetchall()})
        except sqlite3.Error as error:
            cases.append({'sql': sql, 'status': 'error', 'type': type(error).__name__, 'message': str(error)})
    print(json.dumps({'sqlite_version': sqlite3.sqlite_version, 'cases': cases,
                      'scope': 'SQLite grouping only; no legacy dialect qualification'}))


if __name__ == '__main__':
    main()
