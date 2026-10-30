"""Record fixed A0/A1 text/blob to INTEGER CAST behavior; no candidate qualification."""
from pathlib import Path
import asyncio,datetime,importlib.metadata,importlib.util,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3];HELPER=ROOT/"artifacts/mdd-033/preflight/probe_temp_policy.py"
spec=importlib.util.spec_from_file_location("reference_helper",HELPER);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
LITERAL_CASES=[
 ("empty",["SELECT CAST('' AS INTEGER) AS v"]),
 ("invalid",["SELECT CAST('bad' AS INTEGER) AS v"]),
 ("prefix",["SELECT CAST('  +00012tail' AS INTEGER) AS v"]),
 ("negative_decimal",["SELECT CAST('-5.9' AS INTEGER) AS v"]),
 ("leading_decimal",["SELECT CAST('.5' AS INTEGER) AS v"]),
 ("exponent",["SELECT CAST('1e5' AS INTEGER) AS v"]),
 ("hex_text",["SELECT CAST('0x10' AS INTEGER) AS v"]),
 ("double_sign",["SELECT CAST('++1' AS INTEGER) AS v"]),
 ("whitespace",["SELECT CAST('\t-12\n' AS INTEGER) AS v"]),
 ("nul_after_digits",["SELECT CAST('+12\x00Z' AS INTEGER) AS v"]),
 ("nul_before_digits",["SELECT CAST('\x00-12' AS INTEGER) AS v"]),
 ("max",["SELECT CAST('9223372036854775807' AS INTEGER) AS v"]),
 ("above_max",["SELECT CAST('9223372036854775808' AS INTEGER) AS v"]),
 ("below_min",["SELECT CAST('-9223372036854775809' AS INTEGER) AS v"]),
 ("oversized",["SELECT CAST('999999999999999999999999999999999999' AS INTEGER) AS v"]),
 ("min",["SELECT CAST('-9223372036854775808' AS INTEGER) AS v"]),
 ("blob_prefix",["SELECT CAST(X'31327461696C' AS INTEGER) AS v"]),
 ("blob_nul",["SELECT CAST(X'31320039' AS INTEGER) AS v"]),
 ("blob_invalid",["SELECT CAST(X'FF3132' AS INTEGER) AS v"]),
 ("null",["SELECT CAST(NULL AS INTEGER) AS v"]),
]
DEX_CASES=[(f"string_{i}",[f"SELECT CAST(value AS INTEGER) AS v FROM strings WHERE string_idx={i}"]) for i in (0,1,2,3,4,5,6)]
async def main():
 helper.require(importlib.metadata.version("mcp")=="2.2.0","MCP identity")
 plan=json.loads((ROOT/"benchmarks/baseline-manifest.json").read_text(encoding="utf8"))
 directory=Path(__file__).resolve().parent/("run-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"));directory.mkdir(exist_ok=False)
 results=[]
 for name in ("A0","A1"):
  variant=next(v for v in plan["variants"] if v["id"]==name)
  for kind,fixture,size,digest,cases in [
   ("literals",ROOT/"tests/fixtures/references/generated/classic-035.dex",660,"076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8",LITERAL_CASES),
   ("dex",ROOT/"tests/fixtures/generated/strings-mutf8-035.dex",224,"4deab5f75b23c118b170005d89a6ebc0d18d894383280253e70de0507d260f35",DEX_CASES)]:
   helper.require(fixture.stat().st_size==size and helper.digest(fixture)==digest,"fixture mismatch")
   helper.FIXTURE=fixture;helper.FIXTURE_SHA=digest;helper.CASES=cases
   output=directory/(name+"-"+kind);output.mkdir()
   value=await helper.probe(variant,output)
   helper.require(helper.digest(fixture)==digest,"fixture changed")
   results.append({"variant":name,"kind":kind,"fixture_sha256":digest,"cases":len(value["cases"]),"observations_sha256":helper.digest(output/(name+".observations.json"))})
 helper.dump(directory/"summary.json",{"scope":"fixed A0/A1 CAST literal and synthetic DEX cases, no candidate or profile qualification","profiles_admitted":False,"private_input_parsed":False,"formal_performance_measurement":False,"driver_sha256":helper.digest(Path(__file__).resolve()),"helper_sha256":helper.digest(HELPER),"records":results})
 print(json.dumps({"directory":str(directory),"records":results}))
if __name__=="__main__":asyncio.run(main())
