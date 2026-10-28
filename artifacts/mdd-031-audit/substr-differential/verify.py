"""Compare the actual candidate binary with prior real A0/A1 observations."""
from pathlib import Path
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[3]
REF = ROOT / "artifacts/mdd-031-audit/substr-preflight/20261028T163305482932Z"
EXE = ROOT / "artifacts/local/sql-independent-target/debug/mdd-independent-substr-probe.exe"
run = subprocess.run([str(EXE)], capture_output=True, text=True, encoding="utf8", timeout=20)
if run.returncode: raise RuntimeError(f"candidate exited {run.returncode}: {run.stderr}")
data = json.loads(run.stdout)
if len(data) != 16: raise RuntimeError("candidate case count")
records = {(entry["dialect"],entry["case"]):entry["output"] for entry in data}
if len(records) != 16: raise RuntimeError("duplicate candidate identity")
for engine in ("A0", "A1"):
    ref = json.loads((REF / f"{engine}.observations.json").read_text(encoding="utf8"))
    for case in ref["cases"]:
        name=case["id"]
        expected=case["statements"][0]["response"]["body"]["statements"][0]["rows"][0][0]
        actual=records[(engine,name)]
        if actual["status"] != "ok": raise RuntimeError(f"{engine}/{name}: {actual}")
        result=actual["result"]
        if result["calculation_complete"] is not True or result["profiles_admitted"] or result["columns"] != ["value"] or len(result["rows"]) != 1: raise RuntimeError(f"{engine}/{name}: incomplete")
        cell=result["rows"][0][0]
        if cell["type"] == "text":
            actual_kind="utf8"
            actual_value=b"".join(unit.to_bytes(2,"little") for unit in cell["value"]["utf16"]).decode("utf-16le",errors="surrogatepass")
        else:
            actual_kind,actual_value=cell["type"],cell.get("value")
        if (actual_kind,actual_value) != (expected["type"],expected.get("value")): raise RuntimeError(f"{engine}/{name}: candidate {(actual_kind,actual_value)!r}, reference {expected!r}")
print(json.dumps({"status":"pass","engines":["A0","A1"],"cases_per_engine":8,"binary_sha256":hashlib.sha256(EXE.read_bytes()).hexdigest(),"reference_observations_sha256":{name:hashlib.sha256((REF/f"{name}.observations.json").read_bytes()).hexdigest() for name in ("A0","A1")},"profiles_admitted":False,"scope":"16 literal-only cases; no full corpus, input coverage, or performance qualification"}))
