"""Observe fixed A0/A1 column schemas and cell tags on one and two DEX inputs."""
from pathlib import Path
import asyncio,datetime,hashlib,importlib.metadata,importlib.util,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3];HELPER=ROOT/"artifacts/mdd-033/preflight/probe_temp_policy.py"
spec=importlib.util.spec_from_file_location("helper",HELPER);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
INPUTS={"one":[(ROOT/"tests/fixtures/references/generated/classic-035.dex",660,"076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8")],"two":[(ROOT/"tests/fixtures/references/generated/classic-035.dex",660,"076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8"),(ROOT/"tests/fixtures/annotations/generated/annotations-038.dex",1452,"65380a8b23601e17339379be211e417d8b4c8383b686b6d173f800656b985360")]}
SINGLE=[
 ("integers","SELECT 0 AS zero,1 AS one,-1 AS negative,9223372036854775807 AS signed_max,9223372036854775808 AS above_signed,NULL AS nothing"),
 ("cast","SELECT CAST('12' AS INTEGER) AS positive,CAST('-12' AS INTEGER) AS negative,CAST('bad' AS INTEGER) AS invalid,CAST(NULL AS INTEGER) AS nothing,CAST(12 AS INTEGER) AS numeric"),
 ("arithmetic","SELECT 1+2 AS plus,1-2 AS minus,0+0 AS zero,1*2 AS product,1/2 AS quotient"),
 ("case","SELECT CASE WHEN 1 THEN 1 ELSE -1 END AS positive,CASE WHEN 0 THEN 1 ELSE -1 END AS negative,CASE WHEN 1 THEN NULL ELSE 1 END AS nothing"),
 ("comparison","SELECT 1=1 AS yes,1=2 AS no,NULL=1 AS unknown"),
 ("dex_source","SELECT file_id,string_count FROM dex_files ORDER BY file_id"),
 ("dex_expression","SELECT file_id,file_id+0 AS plus_zero,CAST(file_id AS INTEGER) AS cast_i64 FROM dex_files ORDER BY file_id"),
 ("strings_source","SELECT string_idx,value FROM strings ORDER BY string_idx LIMIT 3"),
 ("strings_arithmetic","SELECT string_idx,string_idx+0 AS plus_zero,CAST(string_idx AS INTEGER) AS cast_i64 FROM strings ORDER BY string_idx LIMIT 3"),
 ("aggregate","SELECT COUNT(*) AS n,SUM(string_idx) AS sum_idx,MIN(string_idx) AS min_idx,MAX(string_idx) AS max_idx FROM strings WHERE string_idx<3"),
 ("empty_aggregate","SELECT COUNT(*) AS n,SUM(string_idx) AS sum_idx,MIN(string_idx) AS min_idx FROM strings WHERE string_idx=99999"),
 ("source_case","SELECT string_idx,CASE WHEN string_idx=0 THEN NULL ELSE string_idx END AS optional FROM strings ORDER BY string_idx LIMIT 3"),
 ("cte","WITH x AS (SELECT 1 AS n UNION ALL SELECT -1 AS n) SELECT n,n+0 AS plus_zero FROM x ORDER BY n"),
]
MULTI=[
 ("inventory","SELECT file_id,string_pool_id,entry_name,string_count FROM dex_files ORDER BY file_id"),
 ("files_aggregate","SELECT file_id,COUNT(*) AS n,SUM(string_count) AS total FROM dex_files GROUP BY file_id ORDER BY file_id"),
 ("classes_aggregate","SELECT file_id,COUNT(*) AS n FROM classes GROUP BY file_id ORDER BY file_id"),
 ("empty_aggregate","SELECT COUNT(*) AS n,SUM(file_id) AS sum_file FROM dex_files WHERE file_id=99999"),
 ("annotation_nullable","SELECT file_id,annotation_off,ordinal,value_index,value_i64 FROM annotation_elements WHERE file_id=1 ORDER BY annotation_off,ordinal,depth LIMIT 4"),
]
async def probe(variant,directory):
 from mcp import Client
 from mcp.client.stdio import StdioServerParameters
 binary=Path(variant["engine_binary"]["path"]).resolve();helper.require(binary.is_file() and helper.digest(binary)==variant["engine_binary"]["sha256"],"binary identity")
 transcript_path=directory/(variant["id"]+".sdk-transcript.jsonl");transcript=transcript_path.open("x",encoding="utf8",newline="\n");report={"variant":variant["id"],"engine_sha256":helper.digest(binary),"cases":[],"final":None}
 def record(v):transcript.write(json.dumps(v,ensure_ascii=True)+"\n");transcript.flush()
 async def call(client,name,args):
  record({"direction":"request","tool":name,"arguments":args})
  async with asyncio.timeout(5):result=helper.body(await client.call_tool(name,args))
  record({"direction":"response","tool":name,"result":result});return result
 params=StdioServerParameters(command=str(binary),args=["--threads","1","mcp","--timeout-ms","1500","--max-datasets","1"],cwd=ROOT)
 try:
  async with asyncio.timeout(90),Client(params,read_timeout_seconds=5) as client:
   report["server_info"]=client.server_info.model_dump(mode="json",by_alias=True)
   for scope,cases in [("one",SINGLE),("two",MULTI)]:
    opened=await call(client,"open_dataset",{"inputs":[str(i[0]) for i in INPUTS[scope]]});helper.require(not opened["is_error"],"open failed")
    dataset=opened["body"]["dataset_id"];group={"scope":scope,"open":opened,"dataset_id":dataset,"queries":[]};report["cases"].append(group)
    try:
     for name,sql in cases:
      value=await call(client,"query",{"dataset_id":dataset,"sql":[sql],"limit":100,"offset":0});group["queries"].append({"id":name,"sql":sql,"response":value})
    finally:
     group["close"]=await call(client,"close_dataset",{"dataset_id":dataset});helper.require(not group["close"]["is_error"] and group["close"]["body"].get("closed") is True,"close failed")
   report["final"]=await call(client,"list_datasets",{});helper.require(not report["final"]["is_error"],"final list failed")
  report["client_context_exited"]=True;helper.require(helper.digest(binary)==report["engine_sha256"],"binary changed");return report
 finally:
  transcript.close();report["transcript_sha256"]=helper.digest(transcript_path);helper.dump(directory/(variant["id"]+".observations.json"),report)
async def main():
 helper.require(importlib.metadata.version("mcp")=="2.2.0","MCP identity")
 for inputs in INPUTS.values():
  for path,size,digest in inputs:helper.require(path.stat().st_size==size and helper.digest(path)==digest,"fixture identity")
 plan=json.loads((ROOT/"benchmarks/baseline-manifest.json").read_text(encoding="utf8"));directory=Path(__file__).resolve().parent/("run-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"));directory.mkdir(exist_ok=False);records=[]
 for name in ("A0","A1"):
  variant=next(v for v in plan["variants"] if v["id"]==name);value=await probe(variant,directory);records.append({"variant":name,"queries":sum(len(g["queries"]) for g in value["cases"]),"sha256":helper.digest(directory/(name+".observations.json"))})
 for inputs in INPUTS.values():
  for path,size,digest in inputs:helper.require(helper.digest(path)==digest,"fixture changed")
 helper.dump(directory/"summary.json",{"scope":"actual A0/A1 DTO type observations on 1 and 2 synthetic DEX inputs; not candidate equivalence","records":records,"profiles_admitted":False,"private_input_parsed":False,"formal_performance_measurement":False,"driver_sha256":helper.digest(Path(__file__).resolve()),"helper_sha256":helper.digest(HELPER),"inputs":{k:[{"path":str(v[0].relative_to(ROOT)).replace('\\','/'),"bytes":v[1],"sha256":v[2]} for v in seq] for k,seq in INPUTS.items()}})
 print(json.dumps({"directory":str(directory),"records":records}))
if __name__=="__main__":asyncio.run(main())
