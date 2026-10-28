"""Compare the exact legacy decode helper query against a synthetic SQLite oracle."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import sqlite3
import subprocess

ROOT = Path(__file__).resolve().parents[3]
exe = ROOT / "artifacts/local/sql-independent-target/debug/mdd-independent-using-probe.exe"
run = subprocess.run([str(exe)], capture_output=True, text=True, encoding="utf8", timeout=15)
if run.returncode:
    raise RuntimeError(f"independent probe exit={run.returncode}: {run.stderr} {run.stdout}")
result = json.loads(run.stdout)

def cell(value):
    kind, content = value["type"], value.get("value")
    if kind == "null": return None
    if kind in ("i64", "u64"): return int(content)
    if kind == "text":
        return b"".join(unit.to_bytes(2, "little") for unit in content["utf16"]).decode("utf-16le", errors="surrogatepass")
    raise RuntimeError(f"unexpected output type: {kind}")

actual = [tuple(cell(v) for v in row) for row in result["rows"]]
db = sqlite3.connect(":memory:")
db.executescript("CREATE TABLE dex_files(file_id INTEGER PRIMARY KEY, source TEXT, member TEXT, size INTEGER, n_classes INTEGER, n_method_ids INTEGER, n_field_ids INTEGER, n_strings INTEGER); CREATE TABLE methods(file_id INTEGER, method_idx INTEGER, class TEXT, name TEXT, proto TEXT, access TEXT, code_size INTEGER);")
db.executemany("INSERT INTO dex_files VALUES(?,?,?,?,?,?,?,?)", [(1,"one.apk","classes.dex",3,1,2,0,3),(2,"two.dex",None,3,1,2,0,3)])
db.executemany("INSERT INTO methods VALUES(?,?,?,?,?,?,?)", [(1,1,"LA;","f","()V","public",4),(1,2,"LA;","f","()V","public",8),(2,3,"LA;","f","()V","public",1),(3,4,"LA;","f","()V","public",1),(2,5,"LA;","g","()V","public",1)])
sql = "SELECT m.file_id, d.source, d.member FROM methods m JOIN dex_files d USING(file_id) WHERE m.class=? AND m.name=? AND m.proto=?"
ref = db.execute(sql, ("LA;", "f", "()V"))
expected, columns = ref.fetchall(), [x[0] for x in ref.description]
if result["columns"] != columns or Counter(actual) != Counter(expected) or len(actual) != 3 or result.get("calculation_complete") is not True or result.get("profiles_admitted") != []:
    raise RuntimeError(f"mismatch: columns={result['columns']!r}/{columns!r}; rows={actual!r}/{expected!r}")
print(json.dumps({"status":"pass", "probe_sha256":hashlib.sha256(exe.read_bytes()).hexdigest(), "python_sqlite":sqlite3.sqlite_version, "mdd_sqlite":result["sqlite_version"], "columns":columns, "rows":actual, "result_order_significant":False, "profiles_admitted":False, "scope":"synthetic provider and exact legacy helper SQL, native dialect only"}))
