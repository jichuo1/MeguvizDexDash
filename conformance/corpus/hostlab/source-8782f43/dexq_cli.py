"""Portable CLI over the existing dexq MCP implementation; no GUI required."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import analyze
import hostlab

SERVER = Path(__file__).resolve().parent / "dexq/server.py"


def environment(apk=None):
    from huggingface_hub.constants import HF_HUB_CACHE
    env = dict(os.environ)
    env["DEXQ_CACHE_DIR"] = str(hostlab.STATE / "dexq-cache")
    env["DEXQ_ROOTS"] = os.pathsep.join([str(apk.parent)] if apk else
                                       [str(hostlab.ROOT), str(Path(HF_HUB_CACHE).resolve())])
    env["PYTHONIOENCODING"] = "utf-8"
    return env


async def run(args, apk, sample):
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)],
                                   env=environment(apk), cwd=str(SERVER.parent))
    async with Client(params) as client:
        async def call(name, **arguments):
            result = await client.call_tool(name, arguments)
            text = "\n".join(getattr(item, "text", "") for item in result.content)
            if result.is_error:
                raise RuntimeError("dexq rejected operation: " + text[:500])
            return text
        opened = json.loads(await call("open_dataset", inputs=[str(apk)]))
        dataset = opened["dataset_id"]
        if args.command == "index":
            output = json.dumps({"sample": sample, "index": opened}, ensure_ascii=False, indent=2)
        elif args.command == "query":
            output = await call("query", dataset_id=dataset, sql=args.sql, limit=args.limit,
                                max_cell_chars=args.max_cell_chars)
        elif args.command == "decode":
            output = await call("decode", dataset_id=dataset, method=args.method, max_chars=args.max_chars)
        elif args.command == "refs":
            output = await call("find_refs", dataset_id=dataset, kind=args.kind, target=args.target, limit=args.limit)
        elif args.command == "info":
            output = await call("apk_info", path=str(apk))
        else:
            output = await call("describe_tables")
        print(output)
        await call("close_dataset", dataset_id=dataset)


def load_request(path):
    import analysis_plan
    if path.stat().st_size > analysis_plan.MAX_REQUEST_BYTES:
        raise ValueError("analysis request file exceeds 30000 bytes")
    return analysis_plan.validate(json.loads(path.read_text(encoding="utf-8")))


async def run_batch(args, apk, sample, request):
    import analysis_batch
    result = await analysis_batch.execute(apk, request, roots=[apk.parent], sample=sample)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if getattr(args, "output", None):
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered)
    return 0 if result["complete"] else 2


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("mcp", help="Launch stdio server; configure your AI client explicitly")
    sub.add_parser("capabilities", help="Show analysis backends, operations and limits without opening an APK")
    planning = sub.add_parser("plan", help="Explain backend selection without running analysis")
    planning.add_argument("--request", type=Path, required=True)
    batch = sub.add_parser("batch", help="Run a bounded request with one prepared session per backend")
    batch.add_argument("--request", type=Path, required=True)
    batch.add_argument("--output", type=Path)
    source = batch.add_mutually_exclusive_group(required=True)
    source.add_argument("--apk", type=Path)
    source.add_argument("--version-code", type=int)
    batch.add_argument("--sha256")
    batch.add_argument("--revision")
    for name in ("index", "query", "decode", "refs", "info", "tables"):
        command = sub.add_parser(name)
        source = command.add_mutually_exclusive_group(required=True)
        source.add_argument("--apk", type=Path)
        source.add_argument("--version-code", type=int)
        command.add_argument("--sha256")
        command.add_argument("--revision")
        if name == "query":
            command.add_argument("--sql", required=True)
            command.add_argument("--max-cell-chars", type=int, default=300,
                                 help="Cell preview length, 1..16000; use SQL substr() for longer values")
        if name in {"query", "refs", "decode", "info"}:
            command.add_argument("--backend", choices=("sqlite", "dexsql"), default="sqlite")
        if name in {"query", "refs"}:
            command.add_argument("--limit", type=int, default=100)
        if name == "decode":
            command.add_argument("--method", required=True)
            command.add_argument("--max-chars", type=int, default=12000)
        if name == "refs":
            command.add_argument("--kind", choices=("method", "field", "string", "type"), required=True)
            command.add_argument("--target", required=True)
            command.add_argument("--detail", choices=("sites", "methods"), default="sites",
                                 help="DexSQL supports methods; sites preserve legacy offset/op output")
    args = parser.parse_args(argv)
    if args.command == "query" and not 1 <= args.max_cell_chars <= 16000:
        parser.error("--max-cell-chars must be 1..16000")
    if args.command in {"capabilities", "plan"}:
        import analysis_plan
        import install_dexsql
        info = install_dexsql.status()
        result = ({"schema": 1, "dexsql": info, "legacy_default": "sqlite", "jadx": "unchanged",
                   "operations": sorted(analysis_plan.OPERATIONS), "max_tasks": analysis_plan.MAX_TASKS,
                   "max_request_bytes": analysis_plan.MAX_REQUEST_BYTES} if args.command == "capabilities"
                  else analysis_plan.plan(load_request(args.request), dexsql_available=info["available"]))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    request = None
    if args.command == "batch":
        request = load_request(args.request)
    elif getattr(args, "backend", "sqlite") == "dexsql":
        import analysis_plan
        task = {"id": args.command, "operation": args.command, "limit": getattr(args, "limit", 100)}
        if args.command == "query":
            task.update(sql=args.sql, dialect="dexsql")
        elif args.command == "refs":
            task.update(kind=args.kind, target=args.target, detail=args.detail)
        elif args.command == "decode":
            task["method"] = args.method
        request = analysis_plan.validate({"backend": "dexsql", "tasks": [task]})
    if args.command == "mcp":
        os.execve(sys.executable, [sys.executable, str(SERVER)], environment())
    else:
        apk, sample = analyze.inputs(args)
        if request is not None:
            return asyncio.run(run_batch(args, apk, sample, request))
        asyncio.run(run(args, apk, sample))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
