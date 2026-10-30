"""Capture derived-table binding counterexamples and guarded IN cases."""
from pathlib import Path
import hashlib,json,sqlite3,subprocess,sys
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
EXE=ROOT/"artifacts/local/sql-independent-target/debug/examples/sql_bridge_probe.exe"
OUT=HERE/sys.argv[1]
if OUT.exists():raise RuntimeError("refusing to overwrite")
cases=[
 ("derived_in","SELECT d.string_idx IN (1) AS v FROM (SELECT CAST('1' AS TEXT) AS string_idx) d"),
 ("derived_not_in","SELECT d.string_idx NOT IN (1) AS v FROM (SELECT CAST('1' AS TEXT) AS string_idx) d"),
 ("cte_in","WITH d AS (SELECT CAST('1' AS TEXT) AS string_idx) SELECT d.string_idx IN (1) AS v FROM d"),
 ("same_type","SELECT string_idx IN (0) AS v FROM native_strings WHERE string_idx=0"),
 ("same_type_not_in","SELECT string_idx NOT IN (1) AS v FROM native_strings WHERE string_idx=0"),
 ("null_match","SELECT string_idx IN (NULL,0) AS v FROM native_strings WHERE string_idx=0"),
 ("null_no_match","SELECT string_idx IN (NULL,1) AS v FROM native_strings WHERE string_idx=0"),
 ("unknown_column","SELECT missing IN (0) AS v FROM native_strings"),
]
db=sqlite3.connect(":memory:");db.execute("CREATE TABLE native_strings(string_idx INTEGER)");db.execute("INSERT INTO native_strings VALUES(0)")
records=[]
for dialect in ("010","011","native"):
 for name,sql in cases:
  p=subprocess.run([str(EXE),"query",dialect,sql],capture_output=True,text=True,encoding="utf8",timeout=20)
  try: reference={"status":"ok","rows":db.execute(sql).fetchall()}
  except sqlite3.Error as e: reference={"status":"error","message":str(e)}
  records.append({"dialect":dialect,"case":name,"sql":sql,"candidate_exit":p.returncode,"candidate":json.loads(p.stdout),"sqlite":reference})
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
with OUT.open("x",encoding="utf8",newline="\n") as f:
 json.dump({"binary_sha256":sha(EXE),"driver_sha256":sha(Path(__file__)),"sqlite_version":sqlite3.sqlite_version,"cases":records,"profiles_admitted":False,"scope":"derived table and CTE over synthetic metadata, not full dialect qualification"},f,ensure_ascii=True,indent=2);f.write("\n")
print(json.dumps({"path":str(OUT),"sha256":sha(OUT),"cases":len(records)}))
