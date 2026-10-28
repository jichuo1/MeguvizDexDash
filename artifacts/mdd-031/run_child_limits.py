"""Actual owned child checks: reject long chains before constructing an AST."""
import datetime,hashlib,json,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
EXE=ROOT/"target/debug/examples/sql_bridge_probe.exe"
OUT=ROOT/"artifacts/mdd-031/owned-child-limits"
def main():
    records=[]
    for case in ["binary","union","nested"]:
        folder=OUT/case;folder.mkdir(parents=True,exist_ok=True)
        argv=[str(EXE),"stress","native",case];started=datetime.datetime.now(datetime.timezone.utc).isoformat();begin=time.monotonic()
        result=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=8)
        (folder/"stdout.txt").write_bytes(result.stdout);(folder/"stderr.txt").write_bytes(result.stderr)
        record={"argv":argv,"started_utc":started,"elapsed_seconds":time.monotonic()-begin,"exit_code":result.returncode,"stdout_sha256":hashlib.sha256(result.stdout).hexdigest(),"scope":"development rejection test, not performance"}
        (folder/"record.json").write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8")
        if result.returncode!=0:raise RuntimeError("owned child crashed or failed: "+case)
        data=json.loads(result.stdout)
        if not data.get("process_survived") or data["error"]["code"]!="QUOTA_EXCEEDED":raise RuntimeError("wrong stress terminal "+case)
        records.append({"case":case,**record,"error":data["error"],"process_survived":True})
    report={"schema_version":"mdd.sql-owned-child-limits.v1","binary_sha256":hashlib.sha256(EXE.read_bytes()).hexdigest(),"actual_cases":records,"all_child_processes_survived":True,"profile_admitted":False}
    (OUT/"summary.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"owned_child_cases":len(records),"survived":len(records),"actual_quota_terminals":len(records)}))
if __name__=="__main__":main()
