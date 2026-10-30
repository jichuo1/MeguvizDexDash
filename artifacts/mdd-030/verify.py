from datetime import datetime,timezone
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]


def snapshots():
    paths=[ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'rust-toolchain.toml']
    for directory in ['crates/mdd-query','crates/mdd-facts','crates/mdd-dex','crates/mdd-input','crates/mdd-types','tests/fixtures/query']:
        paths.extend(p for p in (ROOT/directory).rglob('*') if p.is_file() and p.suffix in ('.rs','.toml','.json','.py'))
    paths.append(ROOT/'conformance/query/typed-ir-cases.json')
    return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(paths))}


def main():
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ');out=ROOT/'artifacts/mdd-030/validation'/stamp;out.mkdir(parents=True,exist_ok=False)
    before=snapshots();(out/'sources-before.json').write_text(json.dumps(before,indent=2)+'\n',encoding='utf-8',newline='\n')
    commands=[('compiler',['rustc','-Vv']),('small-table-oracle',[sys.executable,'-O','tests/fixtures/query/build_cases.py']),
              ('like-oracle',[sys.executable,'-O','tests/fixtures/query/like_oracle.py']),('codec-oracle',[sys.executable,'-O','tests/fixtures/query/codec_oracle.py']),
              ('check',['cargo','check','--locked','-p','mdd-query','--all-targets']),
              ('clippy',['cargo','clippy','--locked','-p','mdd-query','--all-targets','--','-D','warnings']),
              ('test',['cargo','test','--locked','-p','mdd-query','--','--nocapture']),
              ('format',['cargo','fmt','-p','mdd-query','--','--check'])]
    results=[]
    for name,argv in commands:
        result=subprocess.run([sys.executable,'tools/record_command.py','--output',str(out/name),'--quiet','--']+argv,cwd=ROOT,timeout=180)
        results.append(dict(name=name,exit_code=result.returncode))
        if result.returncode:break
    after=snapshots();stable=before==after;(out/'sources-after.json').write_text(json.dumps(after,indent=2)+'\n',encoding='utf-8',newline='\n')
    binaries={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'target/debug/deps').glob('mdd_query-*') if p.is_file() and p.suffix in ('','.exe')}
    summary=dict(schema_version='mdd.typed-query-validation.v1',source_stable=stable,commands=results,binaries=binaries,
                 profiles_admitted=False,private_inputs=False,formal_performance_runs=0,scope='MDD030 local typed query component, not SQL or M4 terminal/transport qualification')
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'summary':str(out/'summary.json'),'source_stable':stable,'commands':results}))
    if not stable or len(results)!=len(commands) or any(r['exit_code'] for r in results):raise SystemExit(1)


if __name__=='__main__':main()
