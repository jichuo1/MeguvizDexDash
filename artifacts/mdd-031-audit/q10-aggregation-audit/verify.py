"""Independent SQLite oracle and explicit error/coverage checks for frozen Q10."""
from pathlib import Path
import hashlib
import json
import sqlite3
import subprocess

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
EXE = ROOT / "artifacts/local/sql-independent-target/debug/mdd-independent-q10-probe.exe"
FIXTURE = HERE / "fixture.json"
CORPUS = ROOT / "conformance/corpus/hostlab/queries.jsonl"

def require(ok, message):
    if not ok: raise RuntimeError(message)

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

run = subprocess.run([str(EXE)], capture_output=True, text=True, encoding="utf8", timeout=30)
require(run.returncode == 0, f"candidate exit {run.returncode}: {run.stderr}")
observed = json.loads(run.stdout)
data = {entry["mode"]: entry for entry in observed}
require(set(data) == {"normal", "empty", "missing", "source_changed"}, "case set")
frozen = next(json.loads(line) for line in CORPUS.read_text(encoding="utf8").splitlines() if json.loads(line)["id"] == "Q10")
require(data["normal"]["sql"] == frozen["representative_sql"], "SQL differs from frozen Q10")

db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE method_calls(method TEXT, method_class TEXT, method_name TEXT, callee TEXT, callee_class TEXT, callee_name TEXT, file_id INTEGER, class_idx INTEGER, method_idx INTEGER, callee_method_idx INTEGER)")
db.executemany("INSERT INTO method_calls VALUES (?,?,?,?,?,?,?,?,?,?)", json.loads(FIXTURE.read_text(encoding="utf8")))
cur = db.execute(frozen["representative_sql"])
expected = cur.fetchall()
expected_columns = [entry[0] for entry in cur.description]

def cell(value):
    kind, item = value["type"], value.get("value")
    if kind in ("i64", "u64"): return int(item)
    if kind == "null": return None
    if kind == "text": return b"".join(unit.to_bytes(2,"little") for unit in item["utf16"]).decode("utf-16le", errors="surrogatepass")
    raise RuntimeError(f"unexpected type {kind}")

normal = data["normal"]["result"]
require(normal["status"] == "ok", f"normal error: {normal}")
result = normal["result"]
rows = [tuple(cell(value) for value in row) for row in result["rows"]]
require(rows == expected and result["columns"] == expected_columns, f"rows/schema mismatch: {rows!r} versus {expected!r}")
require(len(rows) == 3 and rows[0][3] == 2, "multiplicity")
require(result["calculation_complete"] is True and result["profiles_admitted"] == [], "completion scope")
require(data["normal"]["requires"] == 1 and data["normal"]["opens"] == 1, "normal coverage/cursor")
empty = data["empty"]["result"]
require(empty["status"] == "ok" and empty["result"]["rows"] == [] and empty["result"]["calculation_complete"] is True, "genuine zero-row query")
missing = data["missing"]
require(missing["result"]["status"] == "error" and missing["result"]["error"]["code"] == "INCOMPLETE_FACTS" and missing["result"]["error"]["stage"] == "fixture.coverage", "required relation error masked")
require(missing["requires"] == 1 and missing["opens"] == 0, "LIMIT 0 admitted missing facts")
changed = data["source_changed"]
require(changed["result"]["status"] == "error" and changed["result"]["error"]["code"] == "SOURCE_CHANGED" and changed["result"]["error"]["stage"] == "fixture.cursor", "provider error masked")
require(changed["requires"] == 1 and changed["opens"] == 1, "source change path")
print(json.dumps({"status":"pass", "frozen_query":"Q10", "sqlite_version":sqlite3.sqlite_version, "columns":expected_columns, "ordered_rows":rows, "input_rows":6, "tests":["full ordered rows and duplicate count","genuine zero result","LIMIT 0 incomplete facts","midscan source changed"], "binary_sha256":digest(EXE),"fixture_sha256":digest(FIXTURE),"corpus_sha256":digest(CORPUS),"candidate_result_sha256":hashlib.sha256(run.stdout.encode("utf8")).hexdigest(),"profiles_admitted":False,"scope":"synthetic provider, fixed Q10 and injected provider errors; not real APK or production qualification"},ensure_ascii=True))
