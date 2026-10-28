"""Audit all 54 candidate/reference CAST observations with explicit type differences."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];REF=ROOT/"artifacts/mdd-031-audit/integer-cast-observations/run-20261028T174032300709Z"
def require(ok,message):
 if not ok:raise RuntimeError(message)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
first=json.loads((HERE/"candidate-raw.json").read_text(encoding="utf8"));actual=json.loads((HERE/"candidate-mapped-raw.json").read_text(encoding="utf8"))
first_errors=[x for x in first["cases"] if x["kind"]=="dex" and x["output"]["status"]=="error"]
require(len(first_errors)==14 and all(x["output"]["error"]["message"]=="UNKNOWN_RELATION" for x in first_errors),"initial unmapped failure evidence")
references={}
for name in ("A0","A1"):
 for kind in ("literals","dex"):
  report=json.loads((REF/(name+"-"+kind)/(name+".observations.json")).read_text(encoding="utf8"))
  for case in report["cases"]:
   response=case["statements"][0]["response"];require(not response["is_error"],"reference error")
   statement=response["body"]["statements"][0];require(statement["total_rows"]==1 and not statement["truncated"] and statement["next_offset"] is None,"reference incomplete")
   references[(name,kind,case["id"])]=(case["statements"][0]["sql"],statement["rows"][0][0])
cases=actual["cases"];semantic=type_equal=0;type_differences=[];seen=set();budgets=[]
for item in cases:
 key=(item["engine"],item["kind"],item["id"]);require(key not in seen,"duplicate case");seen.add(key)
 out=item["output"]
 if item["kind"]=="budget":
  expected="CANCELLED" if item["id"]=="cancel" else "QUOTA_EXCEEDED"
  require(out["status"]=="error" and out["error"]["code"]==expected,f"{key} budget/cancel masked")
  budgets.append(key);continue
 require(key in references and out["status"]=="ok",f"{key} candidate error")
 ref_sql,ref=references[key];require(item["reference_sql"]==ref_sql,"reference SQL identity")
 expected_sql=ref_sql.replace("FROM strings","FROM native_strings") if item["kind"]=="dex" else ref_sql
 require(item["candidate_sql"]==expected_sql,"unapproved SQL rewrite")
 result=out["result"];require(result["calculation_complete"] is True and not result["profiles_admitted"] and len(result["rows"])==1,"incomplete candidate")
 cell=result["rows"][0][0];rval=None if ref["type"]=="null" else int(ref["value"]);cval=None if cell["type"]=="null" else int(cell["value"])
 require(rval==cval,f"{key} numerical mismatch {rval}/{cval}");semantic+=1
 rtype={"uint64":"u64","int64":"i64","null":"null"}[ref["type"]]
 if cell["type"]==rtype:type_equal+=1
 else:type_differences.append({"engine":item["engine"],"kind":item["kind"],"id":item["id"],"reference_type":ref["type"],"candidate_type":cell["type"],"value":rval})
require(semantic==54 and type_equal==24 and len(type_differences)==30 and len(budgets)==6,"unexpected counts")
corrupt=actual["actual_corrupt_dex"];direct=corrupt["direct"];bridged=corrupt["bridge"]
require(bridged["status"]=="error" and direct==bridged["error"],"corrupt parser error changed")
require(direct["code"]=="INVALID_INPUT" and direct["stage"]=="dex.annotations" and direct["details"].get("reason")=="ENCODED_VALUE_INDEX" and direct["details"].get("input_coverage")=="partial" and direct["details"].get("facts_coverage")=="unknown","corrupt classification")
print(json.dumps({"status":"pass-scoped","numeric_matches":semantic,"type_matches":type_equal,"type_mismatches":len(type_differences),"type_differences":type_differences,"budget_cancel_checks":len(budgets),"actual_corrupt_dex_error":"INVALID_INPUT/dex.annotations/ENCODED_VALUE_INDEX","first_run_relation_errors_preserved":len(first_errors),"relation_mapping":{"reference":"strings","candidate":"native_strings"},"candidate_raw_sha256":sha(HERE/"candidate-mapped-raw.json"),"source_before_sha256":sha(HERE/"source-before.json"),"profiles_admitted":False,"dto_equivalent":False,"scope":"54 fixed tiny DEX/literal samples, explicit relation mapping; no full SQL/profile or transport qualification"},ensure_ascii=True))
