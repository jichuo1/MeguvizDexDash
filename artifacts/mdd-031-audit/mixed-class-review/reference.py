"""Capture actual fixed DexSQL literal/CAST comparison observations."""
from pathlib import Path
import asyncio
import datetime
import importlib.metadata
import importlib.util
import json
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
HELPER=ROOT/"artifacts/mdd-033/preflight/probe_temp_policy.py"
spec=importlib.util.spec_from_file_location("reference_helper",HELPER)
helper=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
helper.CASES=[
 ("number_text_eq",["SELECT 1='1' AS v"]),
 ("number_text_lt",["SELECT 1<'a' AS v"]),
 ("text_blob_lt",["SELECT 'a'<X'00' AS v"]),
 ("blob_number_gt",["SELECT X'31'>1 AS v"]),
 ("equal_numeric",["SELECT 1=1.0 AS v"]),
 ("null_equal",["SELECT NULL=1 AS v"]),
 ("null_less",["SELECT NULL<'a' AS v"]),
 ("null_not_equal",["SELECT NULL<>NULL AS v"]),
 ("nested",["SELECT ((1))=(('1')) AS v"]),
 ("negative",["SELECT -1<'1' AS v"]),
 ("cast_text_numeric",["SELECT CAST('1' AS TEXT)=1 AS v"]),
 ("cast_numeric_text",["SELECT CAST(1 AS TEXT)=1 AS v"]),
 ("invalid_arithmetic",["SELECT 1+'a' AS v"]),
 ("unknown_column",["SELECT absent=1 AS v FROM strings"]),
]
async def main():
 helper.require(importlib.metadata.version("mcp")=="2.2.0","MCP identity")
 helper.require(helper.FIXTURE.stat().st_size==660 and helper.digest(helper.FIXTURE)==helper.FIXTURE_SHA,"fixture identity")
 plan=json.loads((ROOT/"benchmarks/baseline-manifest.json").read_text(encoding="utf8"))
 directory=Path(__file__).resolve().parent/datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
 directory.mkdir(exist_ok=False)
 records=[]
 for name in ("A0","A1"):
  variant=next(v for v in plan["variants"] if v["id"]==name)
  result=await helper.probe(variant,directory)
  records.append({"variant":name,"cases":len(result["cases"]),"sha256":helper.digest(directory/(name+".observations.json"))})
 helper.require(helper.digest(helper.FIXTURE)==helper.FIXTURE_SHA,"fixture changed")
 helper.dump(directory/"summary.json",{"scope":"fixed reference engines, ASCII comparison samples only", "profiles_admitted":False,"formal_performance_measurement":False,"private_input_parsed":False,"fixture_sha256":helper.FIXTURE_SHA,"driver_sha256":helper.digest(Path(__file__).resolve()),"helper_sha256":helper.digest(HELPER),"records":records})
 print(json.dumps({"directory":str(directory),"records":records}))
if __name__=="__main__": asyncio.run(main())
