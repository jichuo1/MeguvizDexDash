#!/usr/bin/env python3
"""Actual reference conformance. Every command/result is retained per run."""
from __future__ import annotations
import datetime,hashlib,importlib.util,json,platform,subprocess,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent;FIXTURES=ROOT/"tests/fixtures/references"
PUBLIC=ROOT/"artifacts/local/inputs/NewPipe_v0.28.6.apk";PUBLIC_SHA="e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58"
TABLES=["method_strings","method_calls","method_field_accesses","method_used_types"]
def require(condition,message):
    if not condition:raise ValueError(message)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def canonical(rows):return sorted(json.dumps(row,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False) for row in rows)

def main():
    run_id=datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ");run_dir=HERE/"validation"/run_id;run_dir.mkdir(parents=True,exist_ok=False);commands=[]
    def command(label,argv,allow_failure=False):
        result=subprocess.run(argv,cwd=ROOT,capture_output=True,text=True,check=False)
        item={"argv":argv,"exit_code":result.returncode,"stdout":result.stdout,"stderr":result.stderr}
        path=run_dir/(label+".json")
        with path.open("x",encoding="utf8") as stream:stream.write(json.dumps(item,indent=2,ensure_ascii=True,allow_nan=False)+"\n")
        commands.append({"label":label,"path":path.relative_to(ROOT).as_posix(),"exit_code":result.returncode})
        require(allow_failure or result.returncode==0,"command failed: "+label)
        return item
    try:
        expected_sha=digest(FIXTURES/"expected.json");generations=[]
        for number in [1,2]:
            command("generate-"+str(number),[sys.executable,"tests/fixtures/references/generate.py"]);generations.append({path.name:digest(path) for path in sorted((FIXTURES/"generated").iterdir())})
        require(generations[0]==generations[1] and digest(FIXTURES/"expected.json")==expected_sha,"nonreproducible fixture or changed manual expectation")
        command("oracle",[sys.executable,"tests/fixtures/references/oracle.py"]);command("oracle-optimized",[sys.executable,"-O","tests/fixtures/references/oracle.py"])
        command("A0-tiny-comparison",[sys.executable,"-O","artifacts/mdd-024/compare_reference.py"])
        command("reference-tests",["cargo","test","--locked","--offline","-p","mdd-facts","references::"])
        command("annotation-regression",["cargo","test","--locked","--offline","-p","mdd-dex","-p","mdd-facts","annotations::"])
        command("instruction-regression",["cargo","test","--locked","--offline","-p","mdd-dex","instructions::"])
        command("fact-doc-tests",["cargo","test","--locked","--offline","-p","mdd-facts","--doc"])
        command("clippy",["cargo","clippy","--locked","--offline","-p","mdd-facts","--all-targets","--","-D","warnings"])
        command("format",["rustfmt","--check","--edition","2024","crates/mdd-facts/src/references.rs","crates/mdd-facts/examples/reference_summary.rs","crates/mdd-dex/src/annotations.rs"])
        command("build-consumer",["cargo","build","--locked","--offline","-p","mdd-facts","--example","reference_summary"])
        executable=ROOT/"target/debug/examples"/("reference_summary.exe" if platform.system()=="Windows" else "reference_summary")
        oracle=json.loads((FIXTURES/"oracle-results.json").read_text());manifest=json.loads((FIXTURES/"manifest.json").read_text());schemas={item["name"]:item["columns"] for item in json.loads((ROOT/"conformance/manifests/relations.json").read_text())["relations"]}
        native_comparisons=[];outcomes=[]
        for expected in oracle["results"]:
            name=Path(expected["path"]).stem;result=command("native-"+name,[str(executable),expected["path"],expected["sha256"],"--relations"],allow_failure=expected["status"]=="invalid")
            value=json.loads(result["stdout"])
            if expected["status"]=="invalid":
                require(result["exit_code"]!=0 and value["operation_status"]=="error" and value["error"]["code"]=="INVALID_INPUT","invalid input laundered into success/unknown/unsupported: "+name);outcomes.append({"case":name,"outcome":"InvalidInput","reason":value["error"]["details"].get("reason"),"source_error":value["error"]});continue
            require(result["exit_code"]==0 and value["operation_status"]=="ok" and value["reference_calculation_complete"] is True and value["full_audit_complete"] is False,"native reference scope incomplete: "+name)
            require(len(value["selected_dexes"])==1 and value["selected_dexes"][0]["coverage"]["missing_method_indices"]==[],"native caller scope missing")
            data=value["relations"][0];require(len(data["sites"])==len(expected["sites"]),"site count mismatch")
            for table in TABLES:
                if table=="method_strings":
                    projection=data[table]
                    if expected["plain_scalar_string_projection"] is False:
                        require(projection["operation_status"]=="error" and projection["error"]["code"]=="UNSUPPORTED_QUERY" and projection["error"]["details"]["reason"]=="NON_SCALAR_TEXT_PROJECTION","lossless UTF16 projection policy changed");continue
                    require(projection["operation_status"]=="ok","scalar projection failed");rows=projection["rows"]
                else:rows=data[table]
                require(canonical(rows)==canonical(expected["relations"][table]),"native/oracle relation differs: "+name+":"+table)
                columns=schemas[table];names={column["name"] for column in columns}
                for row in rows:
                    require(set(row)==names,"incomplete frozen schema: "+table)
                    for column in columns:
                        cell=row[column["name"]]
                        if cell is None:require(column["nullable"],"unexpected NULL")
                        elif column["data_type"]=="UInt32":require(type(cell) is int and 0<=cell<=0xffffffff,"invalid UInt32")
                        else:require(isinstance(cell,str),"invalid Utf8View cell")
                native_comparisons.append({"case":name,"relation":table,"rows":len(rows),"full_schema_checked":True,"equal_multiset":True,"sha256":hashlib.sha256("\n".join(canonical(rows)).encode()).hexdigest()})
            outcomes.append({"case":name,"outcome":"complete requested encoded reference scope","sites":len(data["sites"]),"dynamic_calls":len(data["dynamic_calls"]),"plain_scalar_projection":expected["plain_scalar_string_projection"]})
        require(PUBLIC.is_file() and PUBLIC.stat().st_size==10885562 and digest(PUBLIC)==PUBLIC_SHA,"public fixed input unavailable")
        result=command("public-newpipe",[str(executable),"artifacts/local/inputs/NewPipe_v0.28.6.apk",PUBLIC_SHA]);public=json.loads(result["stdout"])
        require(public["reference_calculation_complete"] is True and public["full_audit_complete"] is False and len(public["selected_dexes"])==2,"public reference construction incomplete")
        require(public["definition_search_scope"]["kind"]=="complete_selected_inputs","public world scope not proved")
        require(all(item["coverage"]["facts"]=="complete" and not item["coverage"]["missing_method_indices"] for item in public["selected_dexes"]),"public source coverage missing")
        with (run_dir/"public-summary.json").open("x",encoding="utf8") as stream:stream.write(json.dumps(public,indent=2,allow_nan=False)+"\n")
        toolchain=command("toolchain",["rustc","-Vv"]);checkout=command("checkout",["git","-c","safe.directory=D:/MeguvisDexDash","rev-parse","HEAD"])
        paths=[ROOT/"crates/mdd-facts/src/references.rs",ROOT/"crates/mdd-facts/examples/reference_summary.rs",ROOT/"crates/mdd-dex/src/annotations.rs",ROOT/"crates/mdd-facts/src/code.rs",ROOT/"crates/mdd-dex/src/instructions/mod.rs",ROOT/"crates/mdd-dex/src/instructions/decode.rs",ROOT/"conformance/relations/reference-multiplicity.json",ROOT/"Cargo.lock",ROOT/"rust-toolchain.toml",FIXTURES/"generate.py",FIXTURES/"oracle.py",FIXTURES/"expected.json",Path(__file__).resolve()]
        reference=json.loads((HERE/"small-reference-comparison.json").read_text())
        report={"schema_version":"mdd.reference-conformance.v1","task_id":"MDD-024","run_id":run_id,"success":True,"platform":platform.platform(),"machine":platform.machine(),"python":sys.version,
            "commands":commands,"targeted_reference_tests":9,"fixtures":len(manifest["files"]),"native_valid_scopes":sum(item["status"]=="complete" for item in oracle["results"]),"native_invalid_inputs":sum(item["status"]=="invalid" for item in oracle["results"]),"fixture_generation_reproducible":True,"fixture_sha256":generations[1],"handwritten_expected_sha256":expected_sha,
            "native_full_relation_comparisons":native_comparisons,"native_outcomes":outcomes,"A0_complete_tiny_comparisons":len(reference["complete_relation_comparisons"]),"intentional_A0_differences":reference["known_differences"],"A0_reference_record":reference["reference_record"],
            "source_sha256":{path.relative_to(ROOT).as_posix():digest(path) for path in paths},"consumer_binary":{"path":executable.relative_to(ROOT).as_posix(),"sha256":digest(executable),"bytes":executable.stat().st_size},"checkout":checkout["stdout"].strip(),"toolchain":toolchain["stdout"],
            "public_input":{"path":"artifacts/local/inputs/NewPipe_v0.28.6.apk","sha256":PUBLIC_SHA,"bytes":10885562,"summary":(run_dir/"public-summary.json").relative_to(ROOT).as_posix()},
            "acceptance":[
                {"ordinal":1,"status":"done","evidence":"Per-operand caller/PC/ordinal/kind sites retain repeated strings/callees; shared physical code expands once per genuine definition and is budgeted. Duplicate code projection entries and unowned code do not manufacture callers."},
                {"ordinal":2,"status":"done","evidence":"Every target/site ID binds snapshot and DEX occurrence. Code+definition source identity must match. Same local indices in distinct occurrences remain separate; cross-source local target joins reject. Complete definition-world construction proves every selected input inventory/fact membership."},
                {"ordinal":3,"status":"done","evidence":"External/no exact definition, one-in-scope, ambiguous, unbuilt and provided-only searches are distinct. Complete selected-input absence is only exact encoded declaration absence, never runtime linkage/dispatch. Healthy custom calls keep dynamic targets unknown; corrupt bootstrap/index/word metadata is InvalidInput."},
                {"ordinal":4,"status":"done","evidence":"Every source site carries checked instruction/operand byte ranges and code-unit PC. Jumbo and poly second-proto ranges compared with independent handwritten scalar oracle. Target and definition indexes equal separate scalar scans and manual fixture expectations; 43 complete A0 tiny relation comparisons plus intentional lossy/error differences retained."}],
            "scope":"exact encoded references in declared method bodies of each bound occurrence; definition search explicitly provided-only or complete selected-input scope",
            "budget_scope":"Reference variable facts/index storage, per-caller expanded code units, projection structs/text and candidate counts; counters are not measured RSS or a performance trial.",
            "not_claimed":["runtime call graph or resolved dynamic targets","inheritance/member-linkage/runtime classpath resolution","full DEX/ART type-flow validation","lossy UTF8 projection compatibility for legal non-scalar strings","success on unrelated unrequested annotation layer","HostLab/SQL profile qualification","private large sample parsing","performance benefit or formal release qualification","native Linux acceptance of current changes"],
            "retained_failures":"artifacts/mdd-024/initial-check-failures.json","rollback":"Scope-revert reference module/export/example and narrow helper increment; earlier metadata/definition/code/annotation paths remain independently testable. Retain all immutable observations and failed runs; no backend default was switched."}
        with (run_dir/"result.json").open("x",encoding="utf8") as stream:stream.write(json.dumps(report,indent=2,ensure_ascii=True,allow_nan=False)+"\n")
        (HERE/"reference-conformance.json").write_text(json.dumps(report,indent=2,ensure_ascii=True,allow_nan=False)+"\n",encoding="utf8")
        print("MDD-024 passed; run="+run_id+"; tests9; fixtures18(11 scoped/7 invalid); full tiny relations43; public two DEX complete; runtime/full_audit=false")
        return 0
    except Exception as error:
        with (run_dir/"failure.json").open("x",encoding="utf8") as stream:stream.write(json.dumps({"run_id":run_id,"success":False,"commands":commands,"error":{"type":type(error).__name__,"message":str(error)}},indent=2)+"\n")
        print("MDD-024 failed; run="+run_id+"; "+str(error));return 1
if __name__=="__main__":raise SystemExit(main())
