"""Verify fixed A0/A1 CAST observations and an independent SQLite oracle."""
from pathlib import Path
import hashlib,json,sqlite3,sys
directory=Path(sys.argv[1]);summary=json.loads((directory/"summary.json").read_text(encoding="utf8"))
def require(ok,message):
 if not ok:raise RuntimeError(message)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
inputs={"empty":"","invalid":"bad","prefix":"  +00012tail","negative_decimal":"-5.9","leading_decimal":".5","exponent":"1e5","hex_text":"0x10","double_sign":"++1","whitespace":"\t-12\n","nul_after_digits":"+12\x00Z","nul_before_digits":"\x00-12","max":"9223372036854775807","above_max":"9223372036854775808","below_min":"-9223372036854775809","oversized":"999999999999999999999999999999999999","min":"-9223372036854775808","blob_prefix":b"12tail","blob_nul":b"12\x009","blob_invalid":b"\xff12","null":None}
db=sqlite3.connect(":memory:");expected={name:db.execute("SELECT CAST(? AS INTEGER)",(value,)).fetchone()[0] for name,value in inputs.items()}
engine_sha={"A0":"f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448","A1":"602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6"}
records=summary["records"];require(len(records)==4,"record count")
for record in records:
 name,kind=record["variant"],record["kind"];folder=directory/(name+"-"+kind);path=folder/(name+".observations.json")
 require(sha(path)==record["observations_sha256"],f"{name}/{kind} digest")
 report=json.loads(path.read_text(encoding="utf8"));require(report["engine_sha256"]==engine_sha[name] and report.get("client_context_exited") is True,"engine identity/context")
 require(sha(folder/(name+".sdk-transcript.jsonl"))==report["transcript_sha256"],"transcript digest")
 cases={c["id"]:c for c in report["cases"]};wanted=inputs if kind=="literals" else {f"string_{i}":None for i in range(7)}
 require(set(cases)==set(wanted),f"{name}/{kind} cases")
 for case_id,case in cases.items():
  response=case["statements"][0]["response"];require(not response["is_error"] and case["close"]["body"].get("closed") is True,f"{name}/{kind}/{case_id} error/close")
  statement=response["body"]["statements"][0];require(statement["total_rows"]==1 and statement["truncated"] is False and statement["next_offset"] is None,"incomplete")
  value=statement["rows"][0][0];actual=None if value["type"]=="null" else int(value["value"]);target=expected[case_id] if kind=="literals" else 0
  require(actual==target,f"{name}/{kind}/{case_id} SQLite value {actual}/{target}")
  target_type=("int64" if kind=="dex" else "null" if target is None else "int64" if target<0 else "uint64")
  require(value["type"]==target_type,f"{name}/{kind}/{case_id} DTO type")
 end=report["active_dataset_after_all_cases"]["body"];require(not end["datasets"] and end["usage"]["datasets"]==0 and end["usage"]["input_bytes"]==0 and end["running_requests"]==0 and end["admitted_requests"]==0,"dataset leak")
print(json.dumps({"status":"pass","engines":["A0","A1"],"literal_cases_per_engine":len(inputs),"dex_cases_per_engine":7,"sqlite_version":sqlite3.sqlite_version,"sqlite_oracle_scope":"20 literal/blob inputs; DEX non-scalar values directly checked against real reference responses, not SQLite","observations_sha256":{x["variant"]+"-"+x["kind"]:x["observations_sha256"] for x in records},"profiles_admitted":False}))
