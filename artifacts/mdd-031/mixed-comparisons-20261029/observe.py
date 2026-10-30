"""Observe fixed engines and current SQL bridge without assuming affinity semantics."""
import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "runs" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
FIXTURE = ROOT / "tests/fixtures/references/generated/classic-035.dex"
ENGINES = {
    "A0": (Path(r"D:\Bilibili_Innocent_Lab\tools\hostlab\vendor\dexsql\0.1.0\dexsql-windows-amd64.exe"), "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448"),
    "A1": (ROOT / "artifacts/local/baseline-engines/A1-0.1.1-windows/dexsql-windows-amd64.exe", "602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6"),
}
CASES = {
    "numeric_text_equal": "SELECT 1='1' AS v",
    "numeric_text_order": "SELECT 1<'a' AS v",
    "text_blob_order": "SELECT 'a'<X'00' AS v",
    "numeric_blob_unequal": "SELECT 1<>X'31' AS v",
    "float_text_equal": "SELECT 1.0='1.0' AS v",
    "null_compare": "SELECT NULL=1 AS v",
    "cast_text_affinity": "SELECT CAST('1' AS TEXT)=1 AS v",
    "cte_text_affinity": "WITH t AS (SELECT CAST('1' AS TEXT) AS x) SELECT x=1 AS v FROM t",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(label, argv):
    folder = OUT / label
    folder.mkdir(parents=True)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    begin = time.monotonic()
    try:
        result = subprocess.run([str(value) for value in argv], cwd=ROOT, capture_output=True, timeout=60)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        code, stdout, stderr = None, error.stdout or b"", error.stderr or b""
    (folder / "stdout.txt").write_bytes(stdout)
    (folder / "stderr.txt").write_bytes(stderr)
    record = {"argv":[str(value) for value in argv], "started_utc":started, "elapsed_seconds":time.monotonic()-begin,
              "exit_code":code, "timed_out":code is None, "stdout_sha256":hashlib.sha256(stdout).hexdigest(),
              "stderr_sha256":hashlib.sha256(stderr).hexdigest()}
    (folder / "record.json").write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8")
    return code, stdout


def table(data):
    rows = [[part.strip() for part in line.strip("|").split("|")] for line in data.decode("utf-8").splitlines() if line.startswith("|")]
    require(len(rows) == 2 and rows[0] == ["v"] and len(rows[1]) == 1, "unexpected reference result")
    return rows[1][0]


def main():
    require(digest(FIXTURE) == "076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8", "fixture changed")
    for name,(path,sha) in ENGINES.items():
        require(digest(path) == sha, name + " identity differs")
    identities = {str(path.relative_to(ROOT)).replace("\\", "/"):digest(path) for path in sorted((ROOT / "crates/mdd-sql").rglob("*.rs"))}
    identities["Cargo.lock"] = digest(ROOT / "Cargo.lock")
    identities["Cargo.toml"] = digest(ROOT / "Cargo.toml")
    code,_ = command("build", ["cargo", "build", "-p", "mdd-sql", "--example", "sql_bridge_probe", "--locked", "--offline", "--jobs", "1"])
    require(code == 0,"probe build failed")
    probe = ROOT / "target/debug/examples/sql_bridge_probe.exe"
    probe_sha = digest(probe)
    sqlite = sqlite3.connect(":memory:")
    observations = []
    for key, sql in CASES.items():
        item = {"id":key,"sql":sql,"sqlite_version":sqlite3.sqlite_version,"sqlite_value":sqlite.execute(sql).fetchone()[0],"engines":{}}
        for name,(path,_) in ENGINES.items():
            code,data=command(name+"/"+key,[path,"--threads","1","query","--input",FIXTURE,"--sql",sql])
            item["engines"][name]={"exit_code":code,"display_value":table(data) if code == 0 else None}
        for dialect in ("native","010","011"):
            code,data=command("bridge-"+dialect+"/"+key,[probe,"query",dialect,sql])
            output=json.loads(data)
            item["engines"]["bridge-"+dialect]={"exit_code":code,"result":output}
        observations.append(item)
    require(digest(probe) == probe_sha and digest(FIXTURE) == "076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8", "probe or input changed")
    require(all(digest(ROOT / name) == sha for name,sha in identities.items()), "source changed")
    require(all(digest(path) == sha for path,sha in ENGINES.values()), "engine changed")
    report={"scope":"observations only; legacy CLI display, Python SQLite and candidate bridge have distinct identities", "profile_admitted":False,
            "fixture_sha256":digest(FIXTURE),"probe_sha256":probe_sha,"source_sha256":identities,"cases":observations}
    (OUT / "observations.json").write_text(json.dumps(report,ensure_ascii=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"path":str(OUT.relative_to(ROOT)),"cases":len(observations),"profile_admitted":False}))


if __name__ == "__main__":
    main()
