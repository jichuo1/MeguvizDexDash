"""Capture Q04 on the bounded synthetic annotation DEX, reference A0/A1."""
from pathlib import Path
import asyncio,datetime,importlib.metadata,importlib.util,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3];HELPER=ROOT/"artifacts/mdd-033/preflight/probe_temp_policy.py"
spec=importlib.util.spec_from_file_location("reference_helper",HELPER);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
corpus=ROOT/"conformance/corpus/hostlab/queries.jsonl";q04=next(json.loads(line) for line in corpus.read_text(encoding="utf8").splitlines() if json.loads(line)["id"]=="Q04")
base=q04["representative_sql"].replace("IN (256)","IN (1000)")
grouped="SELECT file_id,annotation_off,ordinal,value_index FROM annotation_elements WHERE ((file_id=0 AND annotation_off IN (1000,999999)) OR (file_id=1 AND annotation_off IN (1000))) AND depth=1 AND value_kind='string' ORDER BY file_id,annotation_off,ordinal"
helper.CASES=[("dynamic_q04",[base]),("grouped",[grouped])]
helper.FIXTURE=ROOT/"tests/fixtures/annotations/generated/annotations-038.dex";helper.FIXTURE_SHA="65380a8b23601e17339379be211e417d8b4c8383b686b6d173f800656b985360"
async def main():
 helper.require(importlib.metadata.version("mcp")=="2.2.0","MCP identity")
 helper.require(helper.FIXTURE.stat().st_size==1452 and helper.digest(helper.FIXTURE)==helper.FIXTURE_SHA,"fixture identity")
 plan=json.loads((ROOT/"benchmarks/baseline-manifest.json").read_text(encoding="utf8"));directory=Path(__file__).resolve().parent/("reference-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"));directory.mkdir(exist_ok=False)
 records=[]
 for name in ("A0","A1"):
  variant=next(v for v in plan["variants"] if v["id"]==name);value=await helper.probe(variant,directory);records.append({"variant":name,"cases":len(value["cases"]),"sha256":helper.digest(directory/(name+".observations.json"))})
 helper.require(helper.digest(helper.FIXTURE)==helper.FIXTURE_SHA,"fixture changed")
 helper.dump(directory/"summary.json",{"scope":"Q04 dynamic offsets on synthetic annotation DEX; not full HostLab qualification","fixture_sha256":helper.FIXTURE_SHA,"corpus_sha256":helper.digest(corpus),"driver_sha256":helper.digest(Path(__file__).resolve()),"helper_sha256":helper.digest(HELPER),"profiles_admitted":False,"records":records})
 print(json.dumps({"directory":str(directory),"records":records}))
if __name__=="__main__":asyncio.run(main())
