#!/usr/bin/env python3
"""Capture independent SQLite values and prior exact A0 NULL-order evidence."""
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def main():
    a0_path = ROOT / 'artifacts/mdd-031/a0-literals/observations.json'
    a0 = json.loads(a0_path.read_text(encoding='utf8'))
    require(a0['process_exit_code'] == 0 and a0['closed']['closed'] is True, 'A0 terminal incomplete')
    prior = next(x for x in a0['results'] if x['id'] == 'null-order')
    query = 'SELECT 0 AS v UNION ALL SELECT NULL AS v ORDER BY v'
    statement = prior['result']['statements'][0]
    require(prior['sql'] == query and not statement['truncated'] and statement['next_offset'] is None
            and statement['total_rows'] == 2 and statement['rows'] == [
                [{'type':'null','value':None}], [{'type':'uint64','value':'0'}]], 'A0 NULL order differs')
    sqls = {
        'a0_null_order':query,
        'ascending':'SELECT v FROM facts ORDER BY v ASC',
        'descending':'SELECT v FROM facts ORDER BY v DESC',
        'distinct':'SELECT DISTINCT v FROM facts ORDER BY v',
        'groups':'SELECT v,COUNT(*) AS n FROM facts GROUP BY v ORDER BY v',
        'aggregate':'SELECT COUNT(*) AS n,COUNT(v) AS nonnull,COUNT(DISTINCT v) AS distinct_n,MIN(v) AS lo,MAX(v) AS hi,SUM(v) AS total FROM facts',
        'empty_aggregate':'SELECT COUNT(*) AS n,COUNT(v) AS nonnull,MIN(v) AS lo,MAX(v) AS hi,SUM(v) AS total FROM facts',
    }
    db = sqlite3.connect(':memory:')
    records = []
    try:
        db.execute('CREATE TABLE facts(v INTEGER)')
        db.executemany('INSERT INTO facts(v) VALUES (?)', [(None,), (2,), (2,), (-1,)])
        for name, sql in sqls.items():
            if name == 'empty_aggregate': db.execute('DELETE FROM facts')
            cursor = db.execute(sql)
            records.append({'case':name,'sql':sql,'columns':[x[0] for x in cursor.description],
                            'rows':[list(row) for row in cursor.fetchall()]})
    finally:
        db.close()
    require(len(records) == 7 and records[0]['rows'] == [[None],[0]], 'reference results differ')
    result = {'status':'sqlite-reference-complete','sqlite_version':sqlite3.sqlite_version,'records':records,
              'a0_exact_query':{'sql':query,'rows':statement['rows'],
                  'observation_sha256':hashlib.sha256(a0_path.read_bytes()).hexdigest()},
              'scope':'SQLite seven synthetic value queries; A0 only exact null-order query; no DTO/profile qualification'}
    path = HERE / 'sqlite-reference.json'
    with path.open('x',encoding='utf8',newline='\n') as f:
        json.dump(result,f,indent=2); f.write('\n')
    print(json.dumps({'status':result['status'],'sqlite_version':sqlite3.sqlite_version,'cases':len(records)}))


if __name__ == '__main__':
    main()
