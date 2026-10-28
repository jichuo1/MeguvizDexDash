"""Capture literal-case responses from a specific candidate probe binary."""
from pathlib import Path
import hashlib
import json
import sqlite3
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
REF=HERE/"20261028T171701349712Z"
EXE=ROOT/"artifacts/local/sql-independent-target/debug/examples/sql_bridge_probe.exe"
DEST=HERE/sys.argv[1]
if DEST.exists(): raise RuntimeError("refusing to overwrite evidence")
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
db=sqlite3.connect(":memory:")
db.execute("CREATE TABLE strings(value TEXT)")
records=[]
for engine,dialect in [("A0","010"),("A1","011")]:
 ref=json.loads((REF/f"{engine}.observations.json").read_text(encoding="utf8"))
 for case in ref["cases"]:
  sql=case["statements"][0]["sql"]
  adapted=sql.replace("FROM strings","FROM native_strings") if case["id"]=="unknown_column" else sql
  run=subprocess.run([str(EXE),"query",dialect,adapted],capture_output=True,text=True,encoding="utf8",timeout=20)
  candidate=json.loads(run.stdout)
  try:
   cursor=db.execute(sql); sqlite={"status":"ok","rows":cursor.fetchall()}
  except sqlite3.Error as error:
   sqlite={"status":"error","exception":type(error).__name__,"message":str(error)}
  records.append({"engine":engine,"case":case["id"],"sql":sql,"candidate_sql":adapted,"candidate_exit":run.returncode,"candidate":candidate,"sqlite":sqlite})
with DEST.open("x",encoding="utf8",newline="\n") as out:
 json.dump({"binary_sha256":sha(EXE),"driver_sha256":sha(Path(__file__)),"sqlite_version":sqlite3.sqlite_version,"reference_sha256":{n:sha(REF/f"{n}.observations.json") for n in ("A0","A1")},"cases":records,"profiles_admitted":False,"scope":"literal and CAST sample; not full dialect/profile"},out,ensure_ascii=True,indent=2)
 out.write("\n")
print(json.dumps({"path":str(DEST),"sha256":sha(DEST),"binary_sha256":sha(EXE),"cases":len(records)}))
