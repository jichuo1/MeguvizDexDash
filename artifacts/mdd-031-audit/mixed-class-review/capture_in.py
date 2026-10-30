"""Record candidate and SQLite IN/NOT IN results, preserving failures."""
from pathlib import Path
import hashlib,json,sqlite3,subprocess,sys
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
EXE=ROOT/"artifacts/local/sql-independent-target/debug/examples/sql_bridge_probe.exe"
OUT=HERE/sys.argv[1]
if OUT.exists():raise RuntimeError("refusing to overwrite evidence")
cases=[
 ("column_in","SELECT string_idx IN ('0') AS v FROM native_strings WHERE string_idx=0"),
 ("column_not_in","SELECT string_idx NOT IN ('0') AS v FROM native_strings WHERE string_idx=0"),
 ("cast_in","SELECT CAST('01' AS INTEGER) IN ('1') AS v"),
 ("literal_null","SELECT 0 IN ('0',NULL) AS v"),
]
db=sqlite3.connect(":memory:");db.execute("CREATE TABLE native_strings(string_idx INTEGER)");db.execute("INSERT INTO native_strings VALUES(0)")
rows=[]
for dialect in ("010","011","native"):
 for name,sql in cases:
  p=subprocess.run([str(EXE),"query",dialect,sql],capture_output=True,text=True,encoding="utf8",timeout=20)
  rows.append({"dialect":dialect,"case":name,"sql":sql,"candidate_exit":p.returncode,"candidate":json.loads(p.stdout),"sqlite":db.execute(sql).fetchall()})
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
with OUT.open("x",encoding="utf8",newline="\n") as f:
 json.dump({"binary_sha256":sha(EXE),"driver_sha256":sha(Path(__file__)),"sqlite_version":sqlite3.sqlite_version,"cases":rows,"profiles_admitted":False,"scope":"synthetic metadata fixture and CAST; not full dialect/profile"},f,ensure_ascii=True,indent=2);f.write("\n")
print(json.dumps({"path":str(OUT),"sha256":sha(OUT),"cases":len(rows)}))
