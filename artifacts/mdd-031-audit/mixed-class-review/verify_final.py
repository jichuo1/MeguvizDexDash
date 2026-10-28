"""Validate captured IN results and references without overwriting evidence."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
def require(ok,message):
 if not ok:raise RuntimeError(message)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
scope=json.loads((HERE/"candidate-scope-after-join.json").read_text(encoding="utf8"))
in_list=json.loads((HERE/"candidate-in-after-join.json").read_text(encoding="utf8"))
require(scope["binary_sha256"]==in_list["binary_sha256"],"candidate binary mismatch")
def result(c):
 x=c["candidate"]
 if x["operation_status"]=="error":return ("error",x["error"]["code"])
 rows=x["result"]["rows"]
 require(x["result"]["calculation_complete"] is True and not x["result"]["profiles_admitted"] and len(rows)==1 and len(rows[0])==1,"candidate completion")
 v=rows[0][0]
 return ("ok",None if v["type"]=="null" else int(v["value"]))
scope_expected={"derived_in":("error","UNSUPPORTED_QUERY"),"derived_not_in":("error","UNSUPPORTED_QUERY"),"cte_in":("error","UNSUPPORTED_QUERY"),"same_type":("ok",1),"same_type_not_in":("ok",1),"null_match":("ok",1),"null_no_match":("ok",None),"unknown_column":("error","INVALID_ARGUMENT")}
in_expected={"column_in":("error","UNSUPPORTED_QUERY"),"column_not_in":("error","UNSUPPORTED_QUERY"),"cast_in":("error","UNSUPPORTED_QUERY"),"literal_null":("ok",None)}
for body,expected in [(scope,scope_expected),(in_list,in_expected)]:
 require(len(body["cases"])==len(expected)*3,"case count")
 for case in body["cases"]:require(result(case)==expected[case["case"]],f"{case['dialect']}/{case['case']} unexpected")
for dirname,expected in [("in-20261028T172359975146Z",{"column_in":1,"column_not_in":0,"cast_in":1,"literal_null":None}),("scope-20261028T172702255061Z",{"derived_in":1,"derived_not_in":0})]:
 for name in ("A0","A1"):
  report=json.loads((HERE/dirname/f"{name}.observations.json").read_text(encoding="utf8"));require(report.get("client_context_exited") is True,"reference context")
  cases={c["id"]:c for c in report["cases"]};require(set(cases)==set(expected),"reference cases")
  for case_id,want in expected.items():
   case=cases[case_id];response=case["statements"][0]["response"];require(not response["is_error"] and case["close"]["body"].get("closed") is True,"reference error or close")
   stmt=response["body"]["statements"][0];require(stmt["total_rows"]==1 and not stmt["truncated"] and stmt["next_offset"] is None,"reference incomplete")
   value=stmt["rows"][0][0];actual=None if value["type"]=="null" else int(value["value"]);require(actual==want,f"{dirname}/{name}/{case_id}")
  final=report["active_dataset_after_all_cases"]["body"];require(not final["datasets"] and final["usage"]["input_bytes"]==0 and final["usage"]["datasets"]==0,"reference dataset leak")
print(json.dumps({"status":"pass","candidate_binary_sha256":scope["binary_sha256"],"scope_cases":len(scope["cases"]),"in_cases":len(in_list["cases"]),"reference_engines":["A0","A1"],"candidate_in_sha256":sha(HERE/"candidate-in-after-join.json"),"candidate_scope_sha256":sha(HERE/"candidate-scope-after-join.json"),"profiles_admitted":False,"scope":"known guarded subset only; mixed affinity and derived comparisons remain unsupported"}))
