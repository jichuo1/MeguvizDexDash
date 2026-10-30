#!/usr/bin/env python3
"""Record actual SQLite LIKE edge observations, without claiming DexSQL equivalence."""
import json
import sqlite3


def main():
    db = sqlite3.connect(':memory:')
    statements = [
        "SELECT 'a' LIKE 'a!' ESCAPE '!'",
        "SELECT '' LIKE '!' ESCAPE '!'",
        "SELECT NULL LIKE 'a' ESCAPE ''",
        "SELECT 'a' LIKE NULL ESCAPE ''",
        "SELECT '😀' LIKE '_'",
        "SELECT '😀' LIKE '😀' ESCAPE '😀'",
    ]
    out = []
    for sql in statements:
        try:
            out.append({'sql': sql, 'value': db.execute(sql).fetchone()[0], 'status': 'ok'})
        except sqlite3.Error as error:
            out.append({'sql': sql, 'status': 'error', 'error_type': type(error).__name__, 'message': str(error)})
    print(json.dumps({'sqlite_version': sqlite3.sqlite_version, 'cases': out,
                      'scope': 'SQLite observation only; A0/A1 not tested',
                      'profiles_admitted': False}, ensure_ascii=False))


if __name__ == '__main__':
    main()
