#!/usr/bin/env python3
"""Observe actual SQLite min/max arity, NULL, storage classes and collation."""
import json
from pathlib import Path
import sqlite3
import struct

HERE=Path(__file__).resolve().parent
CASES={
 'zero_min':'SELECT min() AS v',
 'zero_max':'SELECT max() AS v',
 'one_literal':'SELECT min(2) AS lo,max(2) AS hi',
 'one_column':'SELECT min(v) AS lo,max(v) AS hi FROM facts',
 'empty_aggregate':'SELECT min(v) AS lo,max(v) AS hi FROM facts WHERE 0',
 'one_null':'SELECT min(NULL) AS lo,max(NULL) AS hi',
 'numeric_pair':'SELECT min(2,1) AS lo,max(2,1) AS hi',
 'numeric_three':'SELECT min(2,1,3) AS lo,max(2,1,3) AS hi',
 'null_second':'SELECT min(5,NULL) AS lo,max(5,NULL) AS hi',
 'null_first':'SELECT min(NULL,5) AS lo,max(NULL,5) AS hi',
 'null_third':'SELECT min(1,2,NULL) AS lo,max(1,2,NULL) AS hi',
 'mixed_number_text':'SELECT min(1,\'0\') AS lo,max(1,\'0\') AS hi',
 'mixed_text_blob':'SELECT min(\'z\',x\'00\') AS lo,max(\'z\',x\'00\') AS hi',
 'binary_text':'SELECT min(\'a\',\'B\') AS lo,max(\'a\',\'B\') AS hi',
 'nocase_left':'SELECT min(\'a\' COLLATE NOCASE,\'B\') AS lo,max(\'a\' COLLATE NOCASE,\'B\') AS hi',
 'nocase_right':'SELECT min(\'a\',\'B\' COLLATE NOCASE) AS lo,max(\'a\',\'B\' COLLATE NOCASE) AS hi',
 'binary_then_nocase':'SELECT min(\'a\' COLLATE BINARY,\'B\' COLLATE NOCASE) AS lo,max(\'a\' COLLATE BINARY,\'B\' COLLATE NOCASE) AS hi',
 'nocase_then_binary':'SELECT min(\'a\' COLLATE NOCASE,\'B\' COLLATE BINARY) AS lo,max(\'a\' COLLATE NOCASE,\'B\' COLLATE BINARY) AS hi',
 'reversed_collations':'SELECT min(\'B\' COLLATE NOCASE,\'a\' COLLATE BINARY) AS lo,max(\'B\' COLLATE NOCASE,\'a\' COLLATE BINARY) AS hi',
 'column_binding':'SELECT min(c,d) AS cd_lo,max(c,d) AS cd_hi,min(d,c) AS dc_lo,max(d,c) AS dc_hi FROM facts WHERE id=1',
 'column_explicit':'SELECT min(c,d COLLATE BINARY) AS cd_lo,min(d,c COLLATE NOCASE) AS dc_lo FROM facts WHERE id=1',
 'column_null':'SELECT min(v,5) AS lo,max(v,5) AS hi FROM facts WHERE id=2',
 'column_multirow':'SELECT id,min(c,d) AS lo,max(c,d) AS hi FROM facts ORDER BY id',
}


def cell(v):
    if v is None:return {'type':'null','value':None}
    if isinstance(v,int):return {'type':'integer','value':str(v)}
    if isinstance(v,float):return {'type':'real','f64_be_hex':struct.pack('>d',v).hex()}
    if isinstance(v,str):return {'type':'text','value':v}
    if isinstance(v,bytes):return {'type':'blob','hex':v.hex()}
    raise TypeError('unexpected SQLite value')


def main():
    db=sqlite3.connect(':memory:');records=[]
    try:
        db.execute('CREATE TABLE facts(id INTEGER PRIMARY KEY,c TEXT COLLATE NOCASE,d TEXT COLLATE BINARY,v INTEGER)')
        db.executemany('INSERT INTO facts VALUES (?,?,?,?)',[(1,'a','B',2),(2,'a','B',None),(3,'z','A',1)])
        for name,sql in CASES.items():
            try:
                cur=db.execute(sql)
                records.append({'case':name,'sql':sql,'status':'ok','columns':[x[0] for x in cur.description],
                                'rows':[[cell(x) for x in row] for row in cur.fetchall()]})
            except sqlite3.Error as error:
                records.append({'case':name,'sql':sql,'status':'error','error_type':type(error).__name__,
                                'message':str(error)})
    finally:db.close()
    if len(records)!=len(CASES):raise RuntimeError('incomplete SQLite reference')
    output={'schema_version':'mdd.minmax.sqlite-observations.v1','sqlite_version':sqlite3.sqlite_version,
            'status':'reference-complete','records':records,
            'scope':'SQLite literal and ordinary-table values only; no A0/A1 or bridge result'}
    with (HERE/'sqlite-reference.json').open('x',encoding='utf8',newline='\n') as f:
        json.dump(output,f,indent=2);f.write('\n')
    print(json.dumps({'status':output['status'],'sqlite_version':sqlite3.sqlite_version,
                      'cases':len(records),'errors':sum(x['status']=='error' for x in records)}))


if __name__=='__main__':main()
