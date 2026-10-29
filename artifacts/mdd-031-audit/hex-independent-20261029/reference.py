#!/usr/bin/env python3
"""Record SQLite and previously saved A0/A1 HEX observations without new legacy runs."""
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT=Path(__file__).resolve().parents[3]
OLD=ROOT/'artifacts/mdd-031/text-projection-20261029/runs/20261028T170439632106Z'


def require(ok,why):
    if not ok:
        raise ValueError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    refs={}
    for engine in ('A0','A1'):
        folder=OLD/(engine+'-hex')
        rec=json.loads((folder/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==0 and not rec['timed_out'],'reference failure')
        for stream in ('stdout','stderr'):
            require(sha(folder/(stream+'.txt'))==rec[stream+'_sha256'],'reference stream drift')
        table={}
        for line in (folder/'stdout.txt').read_text(encoding='utf8').splitlines():
            if line.startswith('|'):
                c=[x.strip() for x in line.strip('|').split('|')]
                if len(c)==2 and c[0] in ('31','34','35'):
                    table[c[0]]=c[1]
        require(table=={'31':'C080','34':'EDA080','35':'EDA0BDEDB880'},'reference values')
        refs[engine]={'rows':table,'record_sha256':sha(folder/'record.json'),'stdout_sha256':rec['stdout_sha256']}
    db=sqlite3.connect(':memory:')
    sqlite={k:db.execute('SELECT hex(CAST(? AS TEXT))',(v,)).fetchone()[0]
            for k,v in {'ascii':'ABC','empty':'','nul':'A\0B','pair':'😀'}.items()}
    sqlite['null']=db.execute('SELECT hex(NULL)').fetchone()[0]
    require(sqlite=={'ascii':'414243','empty':'','nul':'410042','pair':'F09F9880','null':''},'SQLite values')
    print(json.dumps({'status':'passed-reference-only','sqlite_version':sqlite3.sqlite_version,
                      'sqlite':sqlite,'legacy':refs,'legacy_new_runs':0,'profile_admitted':False,
                      'scope':'SQLite literal parameters and saved A0/A1 synthetic DEX rows; no producer equivalence'}))


if __name__=='__main__':
    main()
