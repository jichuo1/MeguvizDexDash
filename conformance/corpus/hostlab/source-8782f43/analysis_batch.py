"""Execute bounded plans with one prepared stdio session per selected backend."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import time
import zipfile

from mcp import Client
from mcp.client.stdio import StdioServerParameters

import analysis_plan
import analysis_paging
import hostlab
import install_dexsql

MAX_RESULT_BYTES = 2 * 1024 * 1024
HERE = Path(__file__).resolve().parent


class BackendError(RuntimeError):
    def __init__(self, message, detail=None):
        super().__init__(message)
        self.detail = detail


def failure(exc):
    # anyio's transport may wrap the useful backend error in nested task groups.
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return {"error": type(exc).__name__, "message": str(exc)[:1000], "detail": getattr(exc, "detail", None)}


def cache_directory():
    return Path(os.environ.get("DEXQ_CACHE_DIR", str(hostlab.STATE / "dexq-cache"))).resolve()


def sqlite_cached(apk):
    # Mirrors legacy schema-1 cache identity without importing/initializing its server.
    stat = apk.stat()
    parts = [(str(apk), stat.st_size, stat.st_mtime_ns)]
    key = hashlib.sha1(json.dumps([1, parts]).encode()).hexdigest()[:16]
    return (cache_directory() / (key + ".sqlite")).is_file()


def controlled_input(apk, roots):
    apk = Path(apk).expanduser().resolve(strict=True)
    roots = [Path(root).expanduser().resolve(strict=True) for root in roots]
    if not apk.is_file() or apk.suffix.lower() not in {".apk", ".dex", ".zip", ".jar"}:
        raise ValueError("analysis input must be an APK/DEX/ZIP/JAR file")
    if not any(apk.is_relative_to(root) for root in roots):
        raise ValueError("analysis input is outside the allowed roots")
    return apk


def archive_inventory(apk):
    """Compare physical DEX members, since native MCP can silently skip malformed members."""
    if apk.stat().st_size > 1024 * 1024 * 1024:
        raise ValueError("source input exceeds 1 GiB budget")
    if apk.suffix.lower() == ".dex":
        return None
    with zipfile.ZipFile(apk) as archive:
        infos = archive.infolist()
        if len(infos) > 100000:
            raise ValueError("archive exceeds entry budget")
        members = [i for i in infos if re.fullmatch(r"classes\d*\.dex", i.filename)]
    names = [i.filename for i in members]
    if not names or len(names) != len(set(names)):
        raise ValueError("archive needs an unambiguous classes*.dex member inventory")
    if sum(i.file_size for i in members) > 1024 * 1024 * 1024:
        raise ValueError("uncompressed DEX exceeds 1 GiB budget")
    return set(names)


def verify_inventory(expected, files):
    # DEX 041 has synthetic #N logical members sharing one physical archive member.
    actual = {re.sub(r"#\d+$", "", name) for name in files.values()}
    if expected is not None and actual != expected:
        raise BackendError("backend did not load the complete physical DEX inventory",
                           {"missing": sorted(expected - actual), "unexpected": sorted(actual - expected)})


def child_environment(apk, threads):
    env = {k:v for k,v in os.environ.items() if not re.search(r"TOKEN|SECRET|PASSWORD|API_KEY", k, re.I)}
    env.update(DEXQ_ROOTS=str(apk.parent), DEXQ_CACHE_DIR=str(cache_directory()),
               DEXQ_WORKERS=str(threads), PYTHONIOENCODING="utf-8")
    return env


def legacy_rows(text):
    lines = text.splitlines()
    if not lines:
        raise BackendError("empty legacy query response")
    columns = lines[0].split("\t")
    rows = [line.split("\t") for line in lines[1:] if not line.startswith("--")]
    if any(len(row) != len(columns) for row in rows):
        raise BackendError("ambiguous legacy tabular result")
    partial = any(line.startswith("--") and "truncated" in line for line in lines)
    return columns, rows, partial


class Session:
    def __init__(self, client, backend, apk, deadline):
        self.client, self.backend, self.apk, self.deadline = client, backend, apk, deadline
        self.dataset = None
        self.files = {}
        self.dead = False

    async def call(self, name, **arguments):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BackendError("analysis deadline exhausted")
        response = await asyncio.wait_for(self.client.call_tool(name, arguments), timeout=remaining)
        text = "\n".join(getattr(item, "text", "") for item in response.content)
        if response.is_error:
            try:
                detail = json.loads(text)
            except ValueError:
                detail = {"message": text[:1000]}
            if detail.get("error", {}).get("dataset_closed"):
                self.dead = True
            raise BackendError("backend rejected operation", detail)
        return json.loads(text) if self.backend == "dexsql" else text

    async def open(self):
        started = time.monotonic()
        opened = await self.call("open_dataset", inputs=[str(self.apk)])
        if self.backend == "sqlite":
            opened = json.loads(opened)
        self.dataset = opened["dataset_id"]
        if self.backend == "sqlite":
            self.files = {r["file_id"]: r["member"] for r in opened["dex_files"]}
        else:
            if not opened.get("has_dex"):
                raise BackendError("input has no readable DEX")
            response = await self.sql("SELECT file_id,entry_name FROM dex_files ORDER BY file_id", 1000)
            if response["partial"]:
                raise BackendError("DEX identity mapping exceeded its budget")
            self.files = {int(row[0]): row[1] for row in response["rows"]}
        return {"backend": self.backend, "prepare_ms": (time.monotonic() - started) * 1000,
                "cache": opened.get("cache", "memory_dataset"), "files": self.files,
                "source_diagnostics": opened.get("diagnostics", [])}

    async def sql(self, sql, limit, offset=0):
        if self.backend == "sqlite":
            raw = await self.call("query", dataset_id=self.dataset, sql=sql, limit=limit, max_cell_chars=16000)
            columns, rows, partial = legacy_rows(raw)
            return {"columns": columns, "rows": rows, "partial": partial, "legacy_text": raw}
        raw = await self.call("query", dataset_id=self.dataset, sql=[sql], limit=limit, offset=offset, timing=True)
        statement = raw["statements"][0]
        return {"columns": [c["name"] for c in statement["columns"]],
                "rows": [[c["value"] for c in row] for row in statement["rows"]],
                "partial": bool(statement["truncated"] or statement["next_offset"] is not None),
                "typed_result": raw}

    def identities(self, response):
        if response["columns"] != ["file_id", "descriptor"]:
            raise BackendError("unexpected method identity columns")
        return [{"file_id": int(row[0]), "entry_name": self.files[int(row[0])], "descriptor": row[1]}
                for row in response["rows"]]

    async def execute(self, task, *, seed=None, progress=None, remaining_bytes=MAX_RESULT_BYTES):
        op, limit = task["operation"], task["limit"]
        if op == "query":
            if self.backend == "sqlite":
                result = await self.sql(task["sql"], limit, task["offset"])
            else:
                pages = analysis_paging.QueryPages(task, seed, remaining_bytes=remaining_bytes)
                if seed is not None and progress is not None:
                    progress(pages.stopped("resume_pending"))
                while True:
                    count = pages.next_limit()
                    if not count:
                        return pages.stopped()
                    try:
                        page = await self.sql(task["sql"], count, pages.cursor)
                        if not pages.admit(page, count):
                            return pages.stopped()
                    except BackendError as exc:
                        error = exc.detail.get("error", {}) if isinstance(exc.detail, dict) else {}
                        if (not self.dead and isinstance(error, dict) and error.get("kind") == "output_too_large"
                                and not error.get("dataset_closed") and pages.shrink_oversized_page(count)):
                            if progress is not None:
                                progress(pages.stopped("native_page_budget_retry"))
                            continue
                        raise
                    except Exception:
                        # The last admitted page is already in the checkpoint; never admit half a page.
                        raise
                    result = pages.stopped()
                    if progress is not None:
                        progress(result)
                    if not result["partial"]:
                        return result
        elif op == "locate":
            sql = analysis_plan.locate_sql(task, self.backend) + f" LIMIT {limit+1}"
            result = await self.sql(sql, limit)
            result["identities"] = self.identities(result)
        elif op == "refs":
            if self.backend == "dexsql":
                result = await self.sql(analysis_plan.refs_sql(task) + f" LIMIT {limit+1}", limit)
                result["identities"] = self.identities(result)
            else:
                raw = await self.call("find_refs", dataset_id=self.dataset, kind=task["kind"],
                                      target=task["target"], limit=limit)
                match = re.search(r"-- (\d+) of (\d+) hit", raw)
                rows = []
                if not raw.startswith("-- 0 hit"):
                    columns, rows, clipped = legacy_rows(raw)
                    if columns != ["file_id", "class", "method", "proto", "offset", "op"]:
                        raise BackendError("unexpected legacy reference columns")
                identities = [{"file_id": int(r[0]), "entry_name": self.files[int(r[0])],
                               "descriptor": r[1] + "->" + r[2] + r[3]} for r in rows]
                # Legacy workers stop at 5000 hits per DEX without a separate cap flag.
                counts = {}
                for identity in identities:
                    counts[identity["file_id"]] = counts.get(identity["file_id"], 0) + 1
                result = {"legacy_text": raw, "identities": identities,
                          "partial": bool(match and match[1] != match[2]) or any(v >= 5000 for v in counts.values()),
                          "reference_detail": task["detail"]}
        elif op == "decode":
            if self.backend == "sqlite":
                raw = await self.call("decode", dataset_id=self.dataset, method=task["method"], max_chars=64000)
                if raw.startswith("not found:"):
                    raise BackendError("method definition not found")
                result = {"smali": raw, "partial": "\n… truncated at" in raw}
            else:
                kwargs = {"dataset_id": self.dataset, "method": task["method"], "max_lines": 1000}
                if "file_id" in task:
                    kwargs["file_id"] = task["file_id"]
                raw = await self.call("decode", **kwargs)
                method = raw["methods"][0]
                body = method["smali"]
                cursor = method["next_offset"]
                while cursor is not None and len(body.encode()) < 64000:
                    page = await self.call("decode", **kwargs, offset=cursor)
                    part = page["methods"][0]
                    if len((body + part["smali"]).encode()) > 64000:
                        break
                    body += part["smali"]
                    next_cursor = part["next_offset"]
                    if next_cursor is not None and next_cursor <= cursor:
                        raise BackendError("decode continuation made no progress")
                    cursor = next_cursor
                result = {"smali": body, "file_id": method["file_id"], "method_idx": method["method_idx"],
                          "code_units": method.get("code_units"), "partial": cursor is not None,
                          "next_offset": cursor}
        else:
            if self.backend == "sqlite":
                result = {"manifest": json.loads(await self.call("apk_info", path=str(self.apk))), "partial": False}
            else:
                raw = await self.call("get_manifest", dataset_id=self.dataset)
                result = {"manifest": raw, "partial": raw.get("next_offset") is not None}
        return result


async def execute(apk, request, *, roots, sample=None, resume=None, checkpoint=None):
    apk = controlled_input(apk, roots)
    expected_members = archive_inventory(apk)
    initial_stat = (apk.stat().st_size, apk.stat().st_mtime_ns)
    request = analysis_plan.validate(request)
    if "resume" in request and resume is None:
        raise ValueError("verified_resume_checkpoint_required")
    native = install_dexsql.status()
    planning = analysis_plan.plan(request, dexsql_available=native["available"], sqlite_cache_hit=sqlite_cached(apk))
    threads = min(request["threads"], os.cpu_count() or 1)
    planning["effective_threads"] = threads
    deadline = time.monotonic() + request["timeout_seconds"]
    report = {"schema": 1, "scope": "offline_static_only", "sample": sample, "plan": planning,
              "result_budget_bytes": MAX_RESULT_BYTES,
              "sessions": [], "tasks": [], "complete": False, "backend_versions": {"sqlite": "legacy-schema-1", "dexsql": native}}
    task_map = {t["id"]:t for t in request["tasks"]}
    saved = {t["id"]: t for t in resume["tasks"]} if resume is not None else {}
    if resume is not None:
        old_backends = {t["id"]: t["backend"] for t in resume["plan"]["tasks"]}
        if old_backends != {t["id"]: t["backend"] for t in planning["tasks"]}:
            raise ValueError("checkpoint_backend_selection_changed")
        report["resume_origin"] = copy.deepcopy(resume["resume_origin"])
        report["sessions"] = [{**copy.deepcopy(s), "checkpoint_reused": True} for s in resume["sessions"] if "files" in s]
        for task in resume["tasks"]:
            if task["status"] == "complete":
                entry = copy.deepcopy(task)
                entry["checkpoint_reused"] = True
                report["tasks"].append(entry)
            elif task["status"] == "partial" and task.get("result", {}).get("rows"):
                report["tasks"].append(copy.deepcopy(task))
    used = sum(analysis_paging.size(t["result"]) for t in report["tasks"] if t["status"] == "complete")
    if used > MAX_RESULT_BYTES:
        raise ValueError("checkpoint_result_budget")
    for entry in report["tasks"]:
        if entry["status"] == "partial":
            entry["result"] = analysis_paging.QueryPages(task_map[entry["id"]], entry["result"],
                remaining_bytes=MAX_RESULT_BYTES-used).stopped("resume_pending")
    def publish(entry):
        report["tasks"] = [t for t in report["tasks"] if t["id"] != entry["id"]]
        report["tasks"].append(entry)
        if checkpoint is not None:
            checkpoint(report, False)
    for group in planning["groups"]:
        backend = group["backend"]
        if backend == "dexsql":
            command = str(install_dexsql.verify())
            args = ["--threads", str(threads), "mcp", "--timeout-ms", str(request["timeout_seconds"] * 1000), "--max-datasets", "1"]
        else:
            import sys
            command, args = sys.executable, [str(HERE / "dexq/server.py")]
        params = StdioServerParameters(command=command, args=args, cwd=str(HERE / "dexq"),
                                      env=child_environment(apk, threads))
        pending = [name for name in group["task_ids"] if saved.get(name, {}).get("status") != "complete"]
        if not pending:
            continue
        try:
            async with asyncio.timeout(max(0.001, deadline - time.monotonic())), Client(params) as client:
                session = Session(client, backend, apk, deadline)
                memo = {}
                try:
                    opened = await session.open()
                    verify_inventory(expected_members, session.files)
                    if resume is not None:
                        previous = next(s for s in resume["sessions"] if s.get("backend") == backend and "files" in s)
                        if session.files != {int(k): v for k, v in previous["files"].items()}:
                            raise BackendError("checkpoint_dex_identity_mapping_changed")
                    report["sessions"] = [s for s in report["sessions"] if s.get("backend") != backend]
                    report["sessions"].append(opened)
                    while pending:
                        name = pending.pop(0)
                        began = time.monotonic()
                        try:
                            task = task_map[name]
                            identity = json.dumps({k:v for k,v in task.items() if k != "id"}, sort_keys=True)
                            reused = memo.get(identity) if task["operation"] != "query" else None
                            seed = saved.get(name, {}).get("result") if saved.get(name, {}).get("status") == "partial" else None
                            def progress(output):
                                publish({"id": name, "backend": backend,
                                    "status": "partial" if output["partial"] else "complete",
                                    "elapsed_ms": (time.monotonic() - began) * 1000,
                                    "reused_from": None, "result": copy.deepcopy(output)})
                            output = reused[1] if reused else await session.execute(task, seed=seed,
                                progress=progress, remaining_bytes=MAX_RESULT_BYTES-used)
                            size = len(json.dumps(output, ensure_ascii=False).encode())
                            if used + size > MAX_RESULT_BYTES:
                                raise BackendError("batch result budget exhausted")
                            used += size
                            publish({"id": name, "backend": backend,
                                "status": "partial" if output["partial"] else "complete",
                                "elapsed_ms": (time.monotonic() - began) * 1000, "reused_from": reused[0] if reused else None,
                                "result": output})
                            if not output["partial"] and task["operation"] != "query":
                                memo[identity] = (name, output)
                        except Exception as exc:
                            admitted = next((t for t in report["tasks"] if t["id"] == name), None)
                            if admitted is not None and admitted["status"] == "partial":
                                admitted["result"].setdefault("pagination", {})["stop_reason"] = (
                                    str(exc) if isinstance(exc, analysis_paging.PageError) else "page_request_failed")
                                admitted["failure"] = failure(exc)
                            else:
                                report["tasks"] = [t for t in report["tasks"] if t["id"] != name]
                                report["tasks"].append({"id": name, "backend": backend, "status": "error",
                                    "reason": str(exc) if isinstance(exc, analysis_paging.PageError) else "backend_request_failed",
                                    "elapsed_ms": (time.monotonic() - began) * 1000, **failure(exc)})
                            detail = exc.detail if isinstance(exc, BackendError) and isinstance(exc.detail, dict) else {}
                            error = detail.get("error", {})
                            if (task_map[name]["operation"] == "query" and not session.dead and isinstance(error, dict)
                                    and not error.get("dataset_closed") and error.get("kind") in {
                                        "invalid_query", "invalid_input", "impl_defined", "output_too_large"}):
                                continue  # A rejected read-only statement does not invalidate the dataset.
                            # A failed/expired dataset is never silently reused or replayed.
                            break
                finally:
                    if session.dataset and not session.dead:
                        try:
                            await asyncio.wait_for(client.call_tool("close_dataset", {"dataset_id": session.dataset}), 3)
                        except Exception:
                            pass  # Client EOF also releases the server and its datasets.
        except Exception as exc:
            report["sessions"].append({"backend": backend, **failure(exc)})
            for entry in report["tasks"]:
                if entry["backend"] == backend and entry["status"] == "partial":
                    entry["result"].get("pagination", {})["stop_reason"] = "analysis_deadline_or_session_failure"
        for name in pending:
            if not any(t["id"] == name for t in report["tasks"]):
                report["tasks"].append({"id": name, "backend": backend, "status": "skipped", "reason": "backend_session_failed_or_deadline"})
    order = {t["id"]:i for i,t in enumerate(request["tasks"])}
    for task in planning["tasks"]:
        if not any(t["id"] == task["id"] for t in report["tasks"]):
            report["tasks"].append({"id": task["id"], "backend": task["backend"], "status": "skipped",
                                    "reason": "backend_session_failed_or_deadline"})
    report["tasks"].sort(key=lambda t:order[t["id"]])
    report["complete"] = len(report["tasks"]) == len(request["tasks"]) and all(t["status"] == "complete" for t in report["tasks"])
    try:
        current_stat = (apk.stat().st_size, apk.stat().st_mtime_ns)
        report["source_unchanged"] = initial_stat == current_stat and (not sample or hostlab.digest(apk) == sample["sha256"])
    except OSError as exc:
        report["source_unchanged"] = False
        report["source_error"] = type(exc).__name__
    report["complete"] = report["complete"] and report["source_unchanged"]
    report["result_bytes"] = sum(analysis_paging.size(t["result"]) for t in report["tasks"] if "result" in t)
    if report["result_bytes"] > MAX_RESULT_BYTES:
        report["complete"] = False
    fresh = [t.get("result", {}).get("pagination", {}) for t in report["tasks"] if not t.get("checkpoint_reused")]
    report["execution"] = {"reused_complete_tasks": sum(bool(t.get("checkpoint_reused")) for t in report["tasks"]),
        "dataset_opens": sum("files" in s and not s.get("checkpoint_reused") for s in report["sessions"]),
        "admitted_query_pages": sum(len(p.get("requests_this_run", [])) for p in fresh),
        "new_query_rows": sum(p.get("fetched_rows", 0) for p in fresh)}
    if checkpoint is not None:
        checkpoint(report, True)
    return report
