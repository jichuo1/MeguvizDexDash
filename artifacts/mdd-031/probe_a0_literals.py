"""Tiny real A0 policy observations; not a production fallback or result producer."""
import datetime,hashlib,json,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"artifacts/mdd-031/a0-literals";OUT.mkdir(parents=True,exist_ok=True)
ENGINE=Path(r"D:\Bilibili_Innocent_Lab\tools\hostlab\vendor\dexsql\0.1.0\dexsql-windows-amd64.exe")
FIXTURE=ROOT/"tests/fixtures/references/generated/classic-035.dex"
QUERIES=[
    ("length-and-text-bytes","SELECT length('😀') AS supplementary_length,length('A\x00B') AS nul_length,hex(CAST('A\x00B' AS TEXT)) AS nul_hex,hex(CAST('😀' AS TEXT)) AS supplementary_hex"),
    ("like-units-case","SELECT 'a_b' LIKE 'a_b' AS literal,'axb' LIKE 'a_b' AS wildcard,'ABC' LIKE 'abc' AS ascii_case,'😀' LIKE '_' AS supplementary_one,'A'||NULL AS concat_null"),
    ("like-escape","SELECT 'a_b' LIKE 'a\\_b' ESCAPE '\\' AS escaped,'a\x00b' LIKE 'a%b' AS nul_like"),
    ("text-order","SELECT '😀' AS v UNION ALL SELECT '\ue000' AS v ORDER BY v"),
    ("casts","SELECT hex(CAST(NULL AS TEXT)) AS null_hex,CAST(9223372036854775807 AS TEXT) AS imax,CAST(18446744073709551615 AS TEXT) AS umax,CAST(1.5 AS TEXT) AS fraction"),
    ("float-bool-casts","SELECT CAST(0 AS BOOLEAN) AS false_value,CAST(1 AS TEXT) AS one,CAST(1.0 AS TEXT) AS float_one,CAST(-0.0 AS TEXT) AS negative_zero,CAST('12' AS BIGINT) AS text_int"),
    ("null-order","SELECT 0 AS v UNION ALL SELECT NULL AS v ORDER BY v"),
]
def main():
    if hashlib.sha256(ENGINE.read_bytes()).hexdigest()!="f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448":raise RuntimeError("A0 identity")
    error=(OUT/"stderr.txt").open("wb");p=subprocess.Popen([str(ENGINE),"-t","1","mcp"],cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=error)
    transcript=[];counter=0;dataset=None;results=[];started=datetime.datetime.now(datetime.timezone.utc).isoformat();begin=time.monotonic()
    def call(method,params):
        nonlocal counter
        counter+=1;q={"jsonrpc":"2.0","id":counter,"method":method,"params":params};p.stdin.write((json.dumps(q)+"\n").encode());p.stdin.flush();transcript.append({"direction":"request","value":q})
        while True:
            line=p.stdout.readline()
            if not line:raise RuntimeError("A0 lost")
            r=json.loads(line);transcript.append({"direction":"response","value":r})
            if r.get("id")==counter:
                if "error" in r:return {"rpc_error":r["error"]}
                result=r["result"]
                if result.get("isError"):return {"tool_error":result}
                if "structuredContent" in result:return result["structuredContent"]
                text="".join(c["text"] for c in result.get("content",[]) if c.get("type")=="text")
                try:return json.loads(text)
                except json.JSONDecodeError:return {"raw_text":text}
    try:
        call("initialize",{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mdd031-policy-observer","version":"1"}})
        p.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n');p.stdin.flush()
        opened=call("tools/call",{"name":"open_dataset","arguments":{"inputs":[str(FIXTURE)]}});dataset=opened["dataset_id"]
        for name,sql in QUERIES:results.append({"id":name,"sql":sql,"result":call("tools/call",{"name":"query","arguments":{"dataset_id":dataset,"sql":[sql],"limit":100}})})
    finally:
        if dataset is not None:closed=call("tools/call",{"name":"close_dataset","arguments":{"dataset_id":dataset}})
        p.stdin.close();p.wait(timeout=10);error.close()
        (OUT/"transcript.jsonl").write_text("".join(json.dumps(r,ensure_ascii=True)+"\n" for r in transcript),encoding="utf-8")
    report={"record_kind":"real_fixed_A0_policy_observations","engine_sha256":hashlib.sha256(ENGINE.read_bytes()).hexdigest(),"input_sha256":hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
        "started_utc":started,"elapsed_seconds":time.monotonic()-begin,"process_exit_code":p.returncode,"closed":closed,"results":results,
        "scope":"tiny literal SQL observations only; no new-engine/profile/performance qualification"}
    (OUT/"observations.json").write_text(json.dumps(report,indent=2,ensure_ascii=True)+"\n",encoding="utf-8")
    print(json.dumps({"queries":len(results),"exit_code":p.returncode,"all_responses_saved":True}))
if __name__=="__main__":main()
