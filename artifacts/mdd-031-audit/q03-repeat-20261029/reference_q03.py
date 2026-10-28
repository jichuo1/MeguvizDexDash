"""Run frozen Q03 on the fixed synthetic DEX in reference A0/A1."""
from pathlib import Path
import asyncio,datetime,importlib.metadata,importlib.util,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3];HELPER=ROOT/"artifacts/mdd-033/preflight/probe_temp_policy.py"
spec=importlib.util.spec_from_file_location("reference_helper",HELPER);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
corpus=ROOT/"conformance/corpus/hostlab/queries.jsonl"
q03=next(json.loads(line) for line in corpus.read_text(encoding="utf8").splitlines() if json.loads(line)["id"]=="Q03")
helper.CASES=[("frozen_q03",[q03["representative_sql"]])]
async def main():
 helper.require(importlib.metadata.version("mcp")=="2.2.0","MCP identity")
 helper.require(helper.FIXTURE.stat().st_size==660 and helper.digest(helper.FIXTURE)==helper.FIXTURE_SHA,"fixture identity")
 plan=json.loads((ROOT/"benchmarks/baseline-manifest.json").read_text(encoding="utf8"))
 directory=Path(__file__).resolve().parent/("reference-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"));directory.mkdir(exist_ok=False)
 results=[]
 for name in ("A0","A1"):
  variant=next(v for v in plan["variants"] if v["id"]==name)
  value=await helper.probe(variant,directory)
  results.append({"variant":name,"cases":len(value["cases"]),"sha256":helper.digest(directory/(name+".observations.json"))})
 helper.require(helper.digest(helper.FIXTURE)==helper.FIXTURE_SHA,"fixture changed")
 helper.dump(directory/"summary.json",{"scope":"fixed Q03 on actual small synthetic DEX; no candidate equivalence or profile qualification","profiles_admitted":False,"fixture_sha256":helper.FIXTURE_SHA,"corpus_sha256":helper.digest(corpus),"driver_sha256":helper.digest(Path(__file__).resolve()),"helper_sha256":helper.digest(HELPER),"records":results})
 print(json.dumps({"directory":str(directory),"records":results}))
if __name__=="__main__":asyncio.run(main())
