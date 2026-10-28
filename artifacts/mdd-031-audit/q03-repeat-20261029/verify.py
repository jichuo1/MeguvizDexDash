"""Compare the frozen Q03 SQL and scope boundaries against independent SQLite."""
from pathlib import Path
import hashlib,json,sqlite3,subprocess
ROOT=Path(__file__).resolve().parents[3];HERE=Path(__file__).resolve().parent
EXE=ROOT/"artifacts/local/sql-independent-target/debug/mdd-independent-q03-probe.exe"
def require(ok,message):
 if not ok:raise RuntimeError(message)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
p=subprocess.run([str(EXE)],capture_output=True,text=True,encoding="utf8",timeout=20)
require(p.returncode==0,f"candidate exit {p.returncode}: {p.stderr}")
cases=json.loads(p.stdout);require(len(cases)==22,"case count")
fixture=json.loads((HERE/"fixture.json").read_text(encoding="utf8"))
db=sqlite3.connect(":memory:")
db.executescript("CREATE TABLE classes(file_id INTEGER,class_idx INTEGER,descriptor TEXT); CREATE TABLE class_interfaces(file_id INTEGER,class_idx INTEGER,ordinal INTEGER,interface_descriptor TEXT,descriptor INTEGER);")
db.executemany("INSERT INTO classes VALUES(?,?,?)",fixture["classes"]);db.executemany("INSERT INTO class_interfaces VALUES(?,?,?,?,?)",fixture["class_interfaces"])
frozen=next(json.loads(line) for line in (ROOT/"conformance/corpus/hostlab/queries.jsonl").read_text(encoding="utf8").splitlines() if json.loads(line)["id"]=="Q03")
def cell(v):
 t=v["type"];x=v.get("value")
 if t in ("i64","u64"):return int(x)
 if t=="null":return None
 if t=="text":return b"".join(z.to_bytes(2,"little") for z in x["utf16"]).decode("utf-16le",errors="surrogatepass")
 raise RuntimeError(f"unknown type {t}")
expected_ok={"q03","numeric_alias","multi_from","correlated_local"}
expected_unsupported={"mixed_alias","derived_shadow","cte_shadow","correlated_outer"}
expected_invalid={"ambiguous","unknown_alias","duplicate_alias"}
for c in cases:
 ident=c["case"];result=c["result"]
 if ident=="q03":require(c["sql"]==frozen["representative_sql"],"Q03 SQL changed")
 try:
  cursor=db.execute(c["sql"]);reference={"status":"ok","columns":[x[0] for x in cursor.description],"rows":cursor.fetchall()}
 except sqlite3.Error as e:reference={"status":"error","message":str(e)}
 if ident in expected_ok:
  require(reference["status"]=="ok" and result["status"]=="ok",f"{c['dialect']}/{ident}: {reference!r} / {result!r}")
  output=result["value"];rows=[tuple(cell(v) for v in row) for row in output["rows"]]
  require(rows==reference["rows"] and output["columns"]==reference["columns"] and output["calculation_complete"] is True and output["profiles_admitted"]==[],f"{c['dialect']}/{ident}: rows/schema mismatch {rows!r}/{reference!r}")
  if ident=="q03":require(len(rows)==3 and rows[0]==rows[1] and rows[2]!=rows[1],"Q03 duplicate loss")
 elif ident in expected_unsupported:
  require(reference["status"]=="ok" and result["status"]=="error" and result["error"]["code"]=="UNSUPPORTED_QUERY",f"{c['dialect']}/{ident}: unsupported boundary mismatch")
 elif ident in expected_invalid:
  require(reference["status"]=="error" and result["status"]=="error" and result["error"]["code"]=="INVALID_ARGUMENT",f"{c['dialect']}/{ident}: real binding error masked")
 else:raise RuntimeError(f"unexpected case {ident}")
print(json.dumps({"status":"pass","sqlite_version":sqlite3.sqlite_version,"dialects":["010","011"],"cases_per_dialect":11,"q03_rows":3,"q03_duplicate_rows":2,"candidate_binary_sha256":sha(EXE),"candidate_raw_sha256":hashlib.sha256(p.stdout.encode("utf8")).hexdigest(),"fixture_sha256":sha(HERE/"fixture.json"),"frozen_corpus_sha256":sha(ROOT/"conformance/corpus/hostlab/queries.jsonl"),"profiles_admitted":False,"scope":"frozen Q03 with synthetic partial schema plus explicit same-name test column; SQLite oracle, not actual HostLab facts"}))
