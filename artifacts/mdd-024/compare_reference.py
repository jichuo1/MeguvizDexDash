#!/usr/bin/env python3
"""Compare complete declared tiny relations; retain stricter native/error differences."""
from __future__ import annotations
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
TABLES=["method_strings","method_calls","method_field_accesses","method_used_types"]
def require(condition,message):
    if not condition:raise ValueError(message)
def canonical(rows):return sorted(json.dumps(row,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False) for row in rows)
def rows(result):
    require("tool_error" not in result,"tool query error");require(len(result["statements"])==1,"statement count")
    item=result["statements"][0];require(item["kind"]=="query" and not item["truncated"] and item["next_offset"] is None,"reference rows not fully delivered")
    columns=[column["name"] for column in item["columns"]];out=[]
    for raw in item["rows"]:
        require(len(raw)==len(columns),"row width");row={}
        for key,cell in zip(columns,raw):
            value=cell["value"]
            if cell["type"] in ["uint64","int64"]:require(isinstance(value,str),"integer precision");value=int(value);require(0<=value<=0xffffffff,"UInt32 projection range")
            row[key]=value
        out.append(row)
    return out
def compare(observation_path):
    observation=json.loads(observation_path.read_text());require(observation["failure"] is None and observation["process_exit_code"]==0,"reference session failed")
    manifest=json.loads((ROOT/"tests/fixtures/references/manifest.json").read_text());oracle=json.loads((ROOT/"tests/fixtures/references/oracle-results.json").read_text())
    expected={item["path"]:item for item in oracle["results"]};records={item["fixture"]:item for item in observation["results"]};sdk={item["fixture"]:item for item in observation["sdk_results"]}
    comparisons=[];differences=[]
    for item in manifest["files"]:
        path=item["path"];reference=records[path];independent=expected[path];require(sdk[path]["input_sha256"]==item["sha256"]==independent["sha256"],"input identities differ")
        if independent["status"]=="invalid":
            differences.append({"fixture":path,"native_expected":"InvalidInput","independent_reason":independent["reason"],"A0_open_error":"open_error" in reference,"A0_successful_query_count":sum("tool_error" not in query["result"] for query in reference.get("queries",[])),"SDK_exit_code":sdk[path]["exit_code"],"scope":"A0/SDK do not validate every requested binding/operand invariant; their success or missing row is not a native golden."});continue
        require(reference.get("input_sha256")==item["sha256"] and "queries" in reference,"reference did not open expected valid reference scope")
        for query in reference["queries"]:
            table=query["table"];actual=rows(query["result"])
            if table=="method_strings" and independent["plain_scalar_string_projection"] is False:
                require(len(actual)==2 and all(row["value"]=="\ufffd" for row in actual),"A0 non-scalar observation changed")
                differences.append({"fixture":path,"relation":table,"native_expected":"raw UTF16 sites complete; plain UTF8 projection UnsupportedQuery","A0_observed":"U+FFFD replacement","profile_admitted":False});continue
            golden=independent["relations"][table];require(canonical(actual)==canonical(golden),"A0/independent rows differ: "+path+":"+table)
            comparisons.append({"fixture":path,"relation":table,"rows":len(actual),"complete_multiset_equal":True,"sha256":hashlib.sha256("\n".join(canonical(actual)).encode()).hexdigest()})
    report={"schema_version":"mdd.reference-small-comparison.v1","success":True,"reference_record":observation_path.relative_to(ROOT).as_posix(),"reference_sha256":hashlib.sha256(observation_path.read_bytes()).hexdigest(),"complete_relation_comparisons":comparisons,"known_differences":differences,"scope":"Complete tiny scalar relation equality only; stricter native corrupt-input rejection and lossless UTF16 policy remain intentional. No general SQL/HostLab/runtime/performance qualification."}
    return report
def main():
    observation=max(HERE.glob("reference-observations-*.json"),key=lambda path:path.stat().st_mtime_ns)
    report=compare(observation);(HERE/"small-reference-comparison.json").write_text(json.dumps(report,indent=2,allow_nan=False)+"\n",encoding="utf8")
    print("complete tiny relation comparisons",len(report["complete_relation_comparisons"]),"; retained known differences",len(report["known_differences"]))
if __name__=="__main__":main()
