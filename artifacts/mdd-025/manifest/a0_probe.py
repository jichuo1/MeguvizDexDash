"""Fully consume fixed A0 summary pages and close its dataset. No fallback."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "artifacts/mdd-025/manifest/a0"
ENGINE = Path(r"D:\Bilibili_Innocent_Lab\tools\hostlab\vendor\dexsql\0.1.0\dexsql-windows-amd64.exe")
PUBLIC = ROOT / "artifacts/local/inputs/NewPipe_v0.28.6.apk"

def require(ok, message):
    if not ok: raise RuntimeError(message)

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    require(hashlib.sha256(ENGINE.read_bytes()).hexdigest() == "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448", "fixed A0 binary identity changed")
    transcript = []
    stderr = (OUT / "stderr.txt").open("wb")
    process = subprocess.Popen([str(ENGINE), "-t", "1", "mcp"], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr)
    request_id = 0
    def call(method, params):
        nonlocal request_id
        request_id += 1
        req = {"jsonrpc":"2.0", "id":request_id, "method":method, "params":params}
        process.stdin.write((json.dumps(req) + "\n").encode()); process.stdin.flush()
        transcript.append({"direction":"request", "value":req})
        while True:
            line = process.stdout.readline()
            require(line, "A0 lost before response")
            value = json.loads(line)
            transcript.append({"direction":"response", "value":value})
            if value.get("id") == request_id:
                require("error" not in value, "A0 RPC error " + str(value))
                result = value["result"]
                require(not result.get("isError", False), "A0 tool error " + str(result))
                if "structuredContent" in result: return result["structuredContent"]
                text = "".join(x["text"] for x in result.get("content", []) if x.get("type") == "text")
                return json.loads(text) if text else result
    dataset = None
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(); begin = time.monotonic()
    try:
        call("initialize", {"protocolVersion":"2024-11-05", "capabilities":{}, "clientInfo":{"name":"mdd-manifest-oracle", "version":"1"}})
        process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'); process.stdin.flush()
        opened = call("tools/call", {"name":"open_dataset", "arguments":{"inputs":[str(PUBLIC)]}})
        (OUT / "open.json").write_text(json.dumps(opened, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
        dataset = opened["dataset_id"]
        pages = []; cursor = 0
        while True:
            page = call("tools/call", {"name":"get_manifest", "arguments":{"dataset_id":dataset,"mode":"summary","limit":2,"offset":cursor}})
            pages.append(page)
            next_offset = page.get("next_offset")
            if next_offset is None: break
            require(isinstance(next_offset, int) and next_offset > cursor, "A0 continuation made no progress")
            cursor = next_offset
        (OUT / "summary-pages.json").write_text(json.dumps(pages, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    finally:
        if dataset is not None:
            closed = call("tools/call", {"name":"close_dataset", "arguments":{"dataset_id":dataset}})
            (OUT / "close.json").write_text(json.dumps(closed, indent=2)+"\n", encoding="utf-8")
        process.stdin.close(); process.wait(timeout=15); stderr.close()
        (OUT / "transcript.jsonl").write_text("".join(json.dumps(x, ensure_ascii=False)+"\n" for x in transcript), encoding="utf-8")
        (OUT / "record.json").write_text(json.dumps({"argv":[str(ENGINE),"-t","1","mcp"],"started_utc":started,
            "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"elapsed_seconds":time.monotonic()-begin,
            "exit_code":process.returncode,"measurement_scope":"development validation, not performance qualification"}, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"pages":len(pages), "summary_keys":list(pages[0])}))

if __name__ == "__main__": main()
