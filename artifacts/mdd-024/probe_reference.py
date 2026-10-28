#!/usr/bin/env python3
"""Read-only tiny A0 relation probes and fixed SDK format observations."""
from __future__ import annotations
import datetime,hashlib,importlib.util,json,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
def require(condition,message):
    if not condition:raise ValueError(message)

def main():
    HERE.mkdir(exist_ok=True)
    manifest=json.loads((ROOT/"tests/fixtures/references/manifest.json").read_text())
    bins=json.loads((ROOT/"conformance/manifests/engine-binaries.json").read_text())["binaries"]
    binary_record=next(value for value in bins if value["version"]=="0.1.0" and value["platform"]=="windows_amd64")
    binary=Path(binary_record["actual_path"]);require(hashlib.sha256(binary.read_bytes()).hexdigest()==binary_record["expected_sha256"],"A0 identity mismatch")
    sdk=Path(r"C:\Users\Administrator\AppData\Local\Android\Sdk\build-tools\37.0.0\dexdump.exe")
    require(hashlib.sha256(sdk.read_bytes()).hexdigest()=="f870af85191214f8f59d78e6a27748f00e724bbcce362115347014419969bcce","SDK identity mismatch")
    spec=importlib.util.spec_from_file_location("mdd022_probe",ROOT/"artifacts/mdd-022/probes/probe_reference.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    probe=module.Probe(binary);results=[];sdk_results=[];failure=None
    try:
        probe.send("initialize",{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mdd024-reference-oracle","version":"1"}})
        probe.send("notifications/initialized",{},notification=True)
        for item in manifest["files"]:
            path=ROOT/item["path"];require(hashlib.sha256(path.read_bytes()).hexdigest()==item["sha256"],"fixture identity mismatch")
            observed=subprocess.run([str(sdk),"-f",str(path)],capture_output=True,timeout=30,check=False)
            sdk_results.append({"fixture":item["path"],"input_sha256":item["sha256"],"exit_code":observed.returncode,"stdout":observed.stdout.decode("utf8","replace"),"stderr":observed.stderr.decode("utf8","replace"),"stdout_raw_sha256":hashlib.sha256(observed.stdout).hexdigest(),"expected":item["format_sdk_expected"]})
            opened=probe.call("open_dataset",{"inputs":[str(path)]})
            if "tool_error" in opened:
                results.append({"fixture":item["path"],"open_error":opened});continue
            dataset=opened["dataset_id"]
            queries=[]
            for table,last in [("method_strings","string_idx"),("method_calls","callee_method_idx"),("method_field_accesses","field_idx"),("method_used_types","type_idx")]:
                sql=f"SELECT * FROM {table} ORDER BY file_id,method_idx,{last}"
                queries.append({"table":table,"sql":sql,"result":probe.call("query",{"dataset_id":dataset,"sql":[sql],"limit":1000})})
            probe.call("close_dataset",{"dataset_id":dataset})
            results.append({"fixture":item["path"],"input_sha256":item["sha256"],"queries":queries})
    except Exception as error:failure={"type":type(error).__name__,"message":str(error)}
    finally:probe.close()
    report={"schema_version":"mdd.reference-observations.v1","time_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"A0":binary_record,"sdk_sha256":hashlib.sha256(sdk.read_bytes()).hexdigest(),"sdk_results":sdk_results,"results":results,"mcp_records":probe.records,"process_exit_code":probe.process.returncode,"stderr":"".join(probe.stderr),"failure":failure,"scope":"Synthetic complete tiny relations and global SDK format observations; not a performance trial, complete engine comparison or runtime target proof"}
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ");output=HERE/("reference-observations-"+stamp+".json")
    with output.open("x",encoding="utf8") as stream:stream.write(json.dumps(report,indent=2,ensure_ascii=True,allow_nan=False)+"\n")
    print("reference observations",len(results),"fixtures; SDK exits",[item["exit_code"] for item in sdk_results],"failure",failure,"saved",output.name)
    for result in results:
        if "queries" not in result:continue
        print(Path(result["fixture"]).name,[(query["table"],len(query["result"].get("statements",[{}])[0].get("rows",[])),"error" if "tool_error" in query["result"] else "ok") for query in result["queries"]])
    return 0 if failure is None else 1
if __name__=="__main__":raise SystemExit(main())
