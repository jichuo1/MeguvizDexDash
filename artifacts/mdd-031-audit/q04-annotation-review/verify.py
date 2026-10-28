"""Check Q04 result tuples against independent oracle, SQLite and fixed A0/A1."""
from pathlib import Path
import hashlib,importlib.util,json,sqlite3,subprocess
ROOT=Path(__file__).resolve().parents[3];HERE=Path(__file__).resolve().parent
EXE=ROOT/"artifacts/local/sql-independent-target/debug/mdd-independent-q04-probe.exe"
REF=HERE/"reference-20261028T174351838494Z";FIELDS=["file_id","annotation_off","depth","ordinal","name_idx","value_off","value_end_off","value_kind","value_index","value_i64","value_f64"]
def require(ok,message):
 if not ok:raise RuntimeError(message)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
p=subprocess.run([str(EXE)],capture_output=True,text=True,encoding="utf8",timeout=20);require(p.returncode==0,f"candidate: {p.stderr}")
candidate=json.loads(p.stdout);cases={(c["dialect"],c["mode"]):c for c in candidate};require(len(cases)==12,"case count")
script=ROOT/"tests/fixtures/annotations/oracle.py";spec=importlib.util.spec_from_file_location("independent_oracle",script);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
fixture=ROOT/"tests/fixtures/annotations/generated/annotations-038.dex";parsed=mod.Oracle(fixture.read_bytes()).read()["annotation_elements"]
rows=[[v[k] for k in FIELDS] for v in parsed if v["annotation_off"]==1000];require(rows==json.loads((HERE/"oracle-fixture.json").read_text(encoding="utf8")),"independent oracle fixture mismatch")
synthetic=json.loads((HERE/"fixture.json").read_text(encoding="utf8"))
db=sqlite3.connect(":memory:");db.execute("CREATE TABLE annotation_elements(file_id INTEGER, annotation_off INTEGER,depth INTEGER,ordinal INTEGER,name_idx INTEGER,value_off INTEGER,value_end_off INTEGER,value_kind TEXT,value_index INTEGER,value_i64 INTEGER,value_f64 REAL)")
def norm(cell):
 if cell["type"]=="null":return None
 if cell["type"]=="u64":return int(cell["value"])
 raise RuntimeError(f"unexpected candidate type {cell!r}")
refs={}
for name in ("A0","A1"):
 report=json.loads((REF/f"{name}.observations.json").read_text(encoding="utf8"));require(report.get("client_context_exited") is True,"reference context")
 end=report["active_dataset_after_all_cases"]["body"];require(not end["datasets"] and end["usage"]["input_bytes"]==0,"reference close")
 for case in report["cases"]:
  response=case["statements"][0]["response"];require(not response["is_error"] and case["close"]["body"].get("closed") is True,"reference error")
  statement=response["body"]["statements"][0];require(statement["total_rows"]==3 and not statement["truncated"] and statement["next_offset"] is None,"reference incomplete")
  refs[(name,case["id"])]=statement
for dialect,engine in [("010","A0"),("011","A1")]:
 for mode in ("q04","grouped","oracle_q04","oracle_grouped"):
  entry=cases[(dialect,mode)];result=entry["result"];require(result["status"]=="ok",f"{dialect}/{mode}: {result}")
  val=result["value"];actual=[tuple(norm(c) for c in row) for row in val["rows"]]
  require(val["calculation_complete"] is True and not val["profiles_admitted"],"candidate completion")
  db.execute("DELETE FROM annotation_elements");db.executemany("INSERT INTO annotation_elements VALUES(?,?,?,?,?,?,?,?,?,?,?)",rows if mode.startswith("oracle_") else synthetic)
  cur=db.execute(entry["sql"]);expected=cur.fetchall();cols=[c[0] for c in cur.description]
  require(actual==expected and val["columns"]==cols,f"{dialect}/{mode} SQLite mismatch")
  if mode.startswith("oracle_"):
   ref=refs[(engine,"dynamic_q04" if mode=="oracle_q04" else "grouped")];require(ref["sql"]==entry["sql"],"reference SQL differs")
   reference=[tuple(None if c["type"]=="null" else int(c["value"]) for c in row) for row in ref["rows"]]
   require(actual==reference and all(c["type"]=="uint64" for row in ref["rows"] for c in row),"fixed reference rows/types")
 for mode,code,stage in [("missing","INCOMPLETE_FACTS","fixture.coverage"),("invalid_input","INVALID_INPUT","fixture.cursor")]:
  entry=cases[(dialect,mode)];require(entry["result"]["status"]=="error" and entry["result"]["error"]["code"]==code and entry["result"]["error"]["stage"]==stage,f"{mode} masked")
  require(entry["requires"]==1 and entry["opens"]==(0 if mode=="missing" else 1),f"{mode} provider path")
print(json.dumps({"status":"pass","dialects":["010","011"],"cases_per_dialect":6,"synthetic_grouped_rows":4,"synthetic_null_rows":1,"dex_oracle_rows":3,"sqlite_version":sqlite3.sqlite_version,"candidate_binary_sha256":sha(EXE),"candidate_raw_sha256":hashlib.sha256(p.stdout.encode("utf8")).hexdigest(),"fixture_sha256":sha(fixture),"oracle_sha256":sha(script),"dto_wire_equal":False,"dto_note":"candidate uses u64 tag while reference uses uint64; values match; no transport adapter validated","invalid_input_note":"deliberate synthetic provider error, not actual corrupted DEX parse","profiles_admitted":False,"scope":"bridge over independent oracle/mock rows, not production fact adapter or full HostLab"}))
