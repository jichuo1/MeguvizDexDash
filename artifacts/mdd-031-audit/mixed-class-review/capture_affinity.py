"""Capture column/CAST/error distinctions versus ordinary SQLite."""
from pathlib import Path
import hashlib
import json
import sqlite3
import subprocess

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
EXE=ROOT/"artifacts/local/sql-independent-target/debug/examples/sql_bridge_probe.exe"
OUT=HERE/"candidate-affinity.json"
if OUT.exists(): raise RuntimeError("refusing to overwrite")
cases=[
 ("numeric_column_text","SELECT string_idx='0' AS v FROM native_strings WHERE string_idx=0"),
 ("text_column_numeric","SELECT value=1 AS v FROM native_strings WHERE string_idx=0"),
 ("text_column_text","SELECT value='I' AS v FROM native_strings WHERE string_idx=0"),
 ("numeric_column_numeric","SELECT string_idx=0 AS v FROM native_strings WHERE string_idx=0"),
 ("numeric_cast_text","SELECT CAST('01' AS INTEGER)='1' AS v"),
 ("bad_cast","SELECT CAST('bad' AS INTEGER)='1' AS v"),
 ("unknown_column","SELECT missing=1 AS v FROM native_strings"),
 ("bad_arithmetic_comparison","SELECT (1+'a')='1' AS v"),
]
db=sqlite3.connect(":memory:")
db.execute("CREATE TABLE native_strings(string_idx INTEGER,value TEXT)")
db.execute("INSERT INTO native_strings VALUES(0,'I')")
records=[]
for dialect in ("010","011","native"):
 for name,sql in cases:
  p=subprocess.run([str(EXE),"query",dialect,sql],capture_output=True,text=True,encoding="utf8",timeout=20)
  candidate=json.loads(p.stdout)
  try: sqlite={"status":"ok","rows":db.execute(sql).fetchall()}
  except sqlite3.Error as e: sqlite={"status":"error","message":str(e)}
  records.append({"dialect":dialect,"case":name,"sql":sql,"candidate_exit":p.returncode,"candidate":candidate,"sqlite":sqlite})
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
with OUT.open("x",encoding="utf8",newline="\n") as f:
 json.dump({"binary_sha256":sha(EXE),"driver_sha256":sha(Path(__file__)),"sqlite_version":sqlite3.sqlite_version,"cases":records,"profiles_admitted":False,"scope":"fixture metadata row versus SQLite ordinary table; SQLite virtual-table oracle separate"},f,ensure_ascii=True,indent=2);f.write("\n")
print(json.dumps({"path":str(OUT),"sha256":sha(OUT),"cases":len(records)}))
