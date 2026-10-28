"""Local MCP gateway to private GitHub Actions. No APK download on this computer."""
import json
import base64
import os
from pathlib import Path
import re
import subprocess
import uuid
import time
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
import hostlab

REPO = "jichuo1/innocent-lab-host-analysis"
WORKFLOW = "host-analysis.yml"
RESULT_PAGE_CHARS = 32000
MAX_RESULT_PAGE_CHARS = 128000
PREVIEW_FILES = {"inventory.json", "job.json", "result.txt", "summary.json", "summary.md", "class.java", "priority-report.md", "report.md", "group.json"}
PAGEABLE_FILES = PREVIEW_FILES | {"priority-summary.json"}
mcp = MCPServer(name="hostlab-remote", instructions="Run bounded APK analysis in GitHub Actions. For cross-version hook-point or structure investigations use plan_version_matrix/submit_version_matrix, advance its durable queue, then collect version_matrix_result pages. For one sample prefer plan_analysis then submit_analysis: related queries reuse input and prepared backends. Raw SQL keeps its declared sqlite/dexsql dialect. Legacy submit_job stays compatible. Reuse returned IDs; never replay an unknown dispatch. APKs stay on the runner. Static candidates do not establish working runtime hooks.")


def gh(args, payload=None):
    result = subprocess.run([os.environ.get("HOSTLAB_GH", "gh"), *args], input=json.dumps(payload) if payload is not None else None,
                            text=True, encoding="utf-8", capture_output=True, timeout=60)
    if result.returncode:
        raise ToolError("GitHub operation failed; check gh login and private analysis repository access")
    return result.stdout


def runs():
    return json.loads(gh(["api", f"repos/{REPO}/actions/workflows/{WORKFLOW}/runs?per_page=50"]))["workflow_runs"]


def source_freshness(summary):
    """Compare metadata with this caller's working tree without rewriting the historical report."""
    import source_snapshot
    result = source_snapshot.compare(summary.get("source_snapshot"), hostlab.ROOT)
    return result


def result_previews(files, out, result_offset, page_chars, result_file, default_file="result.txt"):
    """Render the selected page first; every cursor describes text actually returned."""
    names = {p: str(p.relative_to(out)) for p in files}
    selection = result_file or default_file
    selected = [p for p, name in names.items() if name.replace("\\", "/") == selection
                or "/" not in selection and p.name == selection]
    if len(selected) > 1:
        raise ToolError("Multiple matching result files; select the exact relative result_file")
    chosen = selected[0] if selected else None
    if chosen is None and (result_file or result_offset):
        raise ToolError("No matching result file to page; select a returned relative file path")
    readable = [p for p in files if p.name in PREVIEW_FILES or p == chosen]
    readable.sort(key=lambda p: (p != chosen, names[p]))
    budget = max(page_chars * 3, page_chars + len(names.get(chosen, "")) + 2)
    if budget > MAX_RESULT_PAGE_CHARS * 3:
        raise ToolError("Result file label exceeds the text budget")
    text, pages = [], {}
    used = 0
    truncated = False
    for p in readable:
        content = p.read_text(encoding="utf-8", errors="replace")
        offset = result_offset if p == chosen else 0
        header = names[p] + "\n"
        room = max(0, budget-used-len(header)-(1 if text else 0))
        page = content[offset:offset+min(page_chars, room)]
        end = min(offset+len(page), len(content))
        cursor = {"file": names[p], "offset": offset, "chars": len(page), "total_chars": len(content),
                  "next_offset": end if end < len(content) else None, "page_chars": page_chars}
        pages[names[p]] = cursor
        truncated |= end < len(content)
        if room or used+len(header)+(1 if text else 0) <= budget:
            part = header+page
            used += len(part)+(1 if text else 0)
            text.append(part)
    return {"text": "\n".join(text), "text_truncated": truncated,
            "result_page": pages.get(names.get(chosen)), "file_pages": pages}


def task_summary(files, out):
    counts, failures = {}, []
    clipped = False
    sources = [p for p in files if p.name == "result.txt"]
    for p in sources[:12]:
        if p.stat().st_size > 4*1024*1024:
            clipped = True
            continue
        try:
            value = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError):
            continue
        tasks = value.get("tasks") if isinstance(value, dict) else None
        if not isinstance(tasks, list):
            continue
        clipped |= len(tasks) > 16
        for task in tasks[:16]:
            if not isinstance(task, dict) or task.get("status") not in {"complete", "partial", "error", "skipped"}:
                continue
            status = task["status"]
            counts[status] = counts.get(status, 0)+1
            if status not in {"partial", "error"}:
                continue
            if len(failures) == 32:
                clipped = True
                continue
            failure = task.get("failure") if isinstance(task.get("failure"), dict) else task
            detail = failure.get("detail") or {}
            error = detail.get("error", {}) if isinstance(detail, dict) else {}
            error = error if isinstance(error, dict) else {}
            result = task.get("result") if isinstance(task.get("result"), dict) else {}
            pagination = result.get("pagination") if isinstance(result.get("pagination"), dict) else {}
            reason = pagination.get("stop_reason") or error.get("kind") or task.get("reason") or "incomplete"
            reason = reason if isinstance(reason, str) and re.fullmatch(r"[A-Za-z0-9_:.-]{1,100}", reason) else "backend_error"
            hint = "method_calls_uses_method" if error.get("message") == "unknown column `caller`" else None
            failures.append({"file": str(p.relative_to(out)), "task": str(task.get("id", "unknown"))[:48],
                             "status": status, "reason": reason, "hint": hint,
                             "next_offset": pagination.get("next_offset") if type(pagination.get("next_offset")) is int else None})
    return {"counts": counts, "failures": failures, "truncated": clipped or len(sources)>12}


def repository_report(request_id, result_offset=0, page_chars=RESULT_PAGE_CHARS, result_file=""):
    if not re.fullmatch(r"[0-9a-f]{32}",request_id):
        raise ToolError("Invalid request ID")
    if result_file and Path(result_file).name not in {"report.md", "summary.json"}:
        return None
    try:
        payload=json.loads(gh(["api",f"repos/{REPO}/contents/index.json?ref=reports"]))
        index=json.loads(base64.b64decode(payload["content"]))
    except Exception:
        return None
    rows=[r for r in index.get("reports",[]) if r.get("request_id")==request_id]
    if not rows:
        return None
    entry=max(rows,key=lambda r:r["created_at"])
    path=entry["path"]
    if not re.fullmatch(r"(?:samples/[0-9]+/[0-9a-f]{64}/runs|failures)/[0-9]+-a[0-9]+/report\.md",path):
        raise ToolError("Unexpected report path")
    out=hostlab.STATE/"remote-results"/entry["report_id"]/"repository"
    out.mkdir(parents=True,exist_ok=True)
    files=[]
    for suffix in ("report.md","summary.json"):
        file_path=path.rsplit("/",1)[0]+"/"+suffix
        try:
            blob=json.loads(gh(["api",f"repos/{REPO}/contents/{file_path}?ref=reports"]))
            raw=base64.b64decode(blob["content"])
        except Exception:
            continue
        target=out/suffix
        target.write_bytes(raw)
        files.append(str(target))
    summary_file = out / "summary.json"
    freshness = source_freshness(json.loads(summary_file.read_text(encoding="utf-8"))) if summary_file.exists() else {"status": "unavailable"}
    return {"report_url":f"https://github.com/{REPO}/blob/reports/{path}","release_url":entry.get("release_url"),
            "files":files,**result_previews([Path(p) for p in files],out,result_offset,page_chars,result_file,"report.md"),
            "source":"durable_reports_branch", "source_freshness": freshness}


def lookup(request_id):
    if not re.fullmatch(r"[0-9a-f]{32}", request_id):
        raise ToolError("Invalid request ID")
    mapping = hostlab.STATE / "remote-job-map" / (request_id + ".json")
    journal = hostlab.STATE / "remote-requests" / (request_id + ".json")
    if not mapping.exists() and journal.is_file() and journal.stat().st_size <= 1024 * 1024:
        saved = json.loads(journal.read_text(encoding="utf-8"))
        if type(saved.get("run_id")) is int and saved["run_id"] > 0:
            hostlab.write_json(mapping, {"run_id": saved["run_id"]})
    if mapping.exists():
        run_id = int(json.loads(mapping.read_text(encoding="utf-8"))["run_id"])
        return json.loads(gh(["api", f"repos/{REPO}/actions/runs/{run_id}"]))
    run = next((r for r in runs() if r["display_title"] == "hostlab-" + request_id), None)
    if run is not None:
        hostlab.write_json(mapping, {"run_id": run["id"]})
    return run


@mcp.tool()
def plan_version_matrix(samples: list[dict], request: dict, max_parallel: int = 4,
                        reuse_completed: bool = True, deadline_seconds: int = 1800,
                        runner_batch_size: int = 1, execution_policy: str = "fixed") -> str:
    """Plan 1..40 exact APKs over at most 4 runners. Default fixed preserves runner_batch_size=1..4 and old identities. execution_policy=adaptive uses balanced groups (native up to 12, otherwise 4); leave runner_batch_size=1. Its cold projection performs no network/profile reads; exact verified profiles bind at submission. Every sample requires inventory version_code/apk_sha256/sample_revision. No dispatch here."""
    import version_matrix
    try:
        return json.dumps(version_matrix.plan(samples,request,max_parallel,reuse_completed,deadline_seconds,runner_batch_size,
                                              execution_policy),ensure_ascii=False)
    except ValueError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool()
def submit_version_matrix(samples: list[dict], request: dict, max_parallel: int = 4,
                          reuse_completed: bool = True, deadline_seconds: int = 1800,
                          idempotency_key: str = "", runner_batch_size: int = 1,
                          execution_policy: str = "fixed") -> str:
    """Create a durable exact-version queue. Fixed mode keeps runner_batch_size=1..4 and dispatches up to two jobs per call. Adaptive mode snapshots verified performance hints, balances bounded groups and fills up to four physical slots; leave runner_batch_size=1. Stable keys resume the original frozen topology even when profiles/main change. Unknown dispatches and failures never replay automatically."""
    import version_matrix
    try:
        created=version_matrix.create(samples,request,gh,repository=REPO,max_parallel=max_parallel,
            reuse_completed=reuse_completed,deadline_seconds=deadline_seconds,idempotency_key=idempotency_key,
            runner_batch_size=runner_batch_size, execution_policy=execution_policy)
        if "matrix_id" not in created:
            return json.dumps(created)
        return json.dumps(version_matrix.advance(created["matrix_id"],gh,lookup,runs,repository=REPO,
            workflow=WORKFLOW,collect_group=matrix_group_artifact),ensure_ascii=False)
    except ValueError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool()
def advance_version_matrix(matrix_id: str) -> str:
    """Refresh accepted jobs under the captured revision and at most 4 physical slots. Fixed queues dispatch at most two jobs per call; adaptive queues fill up to four. Call only while you intend progress. Capacity pressure keeps local entries; a deadline stops new dispatches without cancelling accepted jobs."""
    import version_matrix
    try:
        return json.dumps(version_matrix.advance(matrix_id,gh,lookup,runs,repository=REPO,
            workflow=WORKFLOW,collect_group=matrix_group_artifact),ensure_ascii=False)
    except ValueError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool()
def version_matrix_status(matrix_id: str) -> str:
    """Refresh matrix job states without submitting additional work."""
    import version_matrix
    try:
        return json.dumps(version_matrix.advance(matrix_id,gh,lookup,runs,repository=REPO,
            workflow=WORKFLOW,dispatch=False,collect_group=matrix_group_artifact),ensure_ascii=False)
    except ValueError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool()
def version_matrix_result(matrix_id: str, offset: int = 0, limit: int = 8, download_parallel: int = 4,
                          prefetch_only: bool = False) -> str:
    """Collect with 1..4 download workers and verified reuse. While later versions run, prefetch_only=true downloads only completed entries on this page, without candidate comparison or dispatch. For final comparisons use prefetch_only=false after the matrix finishes. collection_errors can be retried on the same matrix/page without new Actions. Large comparisons have immutable local snapshots. Static results do not prove working runtime hooks."""
    import version_matrix
    try:
        if prefetch_only:
            return json.dumps(version_matrix.prefetch(matrix_id,matrix_artifact,offset,limit,
                download_parallel=download_parallel),ensure_ascii=False)
        return json.dumps(version_matrix.compare(matrix_id,job_result,offset,limit,
            download_parallel=download_parallel,collect=matrix_artifact),ensure_ascii=False)
    except ValueError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool()
def recover_version_matrix(matrix_id: str, idempotency_key: str = "", include_unverified_results: bool = False) -> str:
    """Retry confirmed failed/skipped versions under the original tool commit and execution policy. Explicit include_unverified_results=true may repeat completed jobs whose member results remain unverified, including earlier successful work. Running/unknown dispatches stay excluded. The same key/opt-in resumes its queue; a new key authorizes another attempt. Uses Actions minutes; fixed/adaptive dispatch at most two/four initial jobs."""
    import version_matrix
    try:
        created = version_matrix.recover(matrix_id, gh, repository=REPO, idempotency_key=idempotency_key,
                                         include_unverified_results=include_unverified_results)
        if "matrix_id" not in created:
            return json.dumps(created)
        return json.dumps(version_matrix.advance(created["matrix_id"], gh, lookup, runs,
            repository=REPO, workflow=WORKFLOW, collect_group=matrix_group_artifact), ensure_ascii=False)
    except ValueError as exc:
        raise ToolError(str(exc)) from None


def matrix_group_artifact(group, payload, run):
    """Collect a physical job once and verify the complete per-version receipt."""
    import remote_artifacts
    import runner_group
    downloaded = remote_artifacts.get(REPO, group["request_id"], run, gh)
    verified = runner_group.collect(payload, downloaded, group["runner_revision"])
    try:
        import adaptive_schedule
        adaptive_schedule.observe(payload, downloaded, group["runner_revision"])
    except Exception:
        # Performance hints are optional; verified results remain authoritative.
        pass
    return verified


def matrix_artifact(entry):
    """Use the matrix's completed run snapshot; old matrices resolve it once per cache access."""
    import remote_artifacts
    run = entry.get("result_run")
    if not run or not {"head_sha", "display_title", "run_attempt"} <= run.keys():
        run = lookup(entry["request_id"])
    if run is None:
        raise remote_artifacts.ArtifactError("result_run_unavailable")
    downloaded = remote_artifacts.get(REPO, entry["request_id"], run, gh)
    if "group_id" in entry:
        import version_matrix
        import runner_group
        matrix = version_matrix.load(entry["matrix_id"])
        group = next(g for g in matrix["groups"] if g["group_id"] == entry["group_id"])
        collected = runner_group.collect(version_matrix.group_payload(matrix, group), downloaded, matrix["runner_revision"])
        member = collected["members"][entry["group_index"]]
        if member["sample"] != entry["sample"] or member["status"] != "complete":
            raise remote_artifacts.ArtifactError("group_member_result_unavailable")
        downloaded = {**downloaded, "files": member["files"]}
    return json.dumps(downloaded, ensure_ascii=False)


@mcp.tool()
def plan_analysis(request: dict) -> str:
    """Plan up to 16 related tasks without dispatching. Request: {backend:auto|sqlite|dexsql,tasks:[{id,operation,...}]}. query requires sql and dialect. DexSQL query.limit is page size; automatic continuation is bounded by pagination={max_pages:1..32,max_rows:1..10000,max_bytes:1024..1048576}, default 8/1000/1048576 and the shared batch deadline/byte budget. max_pages=1 preserves a single page. SQLite SQL is unchanged. locate requires kind/name; refs requires kind/target and methods|sites detail; decode requires a full method descriptor. This is a plan, not execution evidence."""
    import remote_schedule
    try:
        return json.dumps(remote_schedule.describe(request), ensure_ascii=False)
    except ValueError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool()
def submit_analysis(version_code: int, request: dict, apk_sha256: str = "", sample_revision: str = "",
                    idempotency_key: str = "") -> str:
    """Schedule one bounded analysis batch. Related tasks share one APK fetch and one session per backend. DexSQL queries automatically continue under row/page/byte/deadline budgets. request.resume={run_id,attempt,request_id} explicitly imports a verified checkpoint from this repository; exact APK SHA and sample revision are required. Completed task payloads are retained and partial SQL continues at its admitted cursor, never by replaying its prefix. Resume defaults to a stable idempotency key; a new key explicitly authorizes another attempt. Ordinary arbitrary SQL is not completion-cached. Unknown dispatch is never replayed. Uses Actions minutes."""
    import remote_schedule
    try:
        result = remote_schedule.submit(version_code, request, gh, lookup, runs, repository=REPO,
                                        workflow=WORKFLOW, apk_sha256=apk_sha256,
                                        sample_revision=sample_revision, idempotency_key=idempotency_key)
        return json.dumps(result, ensure_ascii=False)
    except ValueError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool()
def submit_job(version_code: int, operation: str, argument: str = "", max_cell_chars: int = 300,
               source_mode: str = "auto") -> str:
    """Submit multipath_audit, audit, decompile (class), query (SELECT SQL), decode (method), string_refs (string), or info. Uses Actions minutes; returns immediately.

    query supports max_cell_chars=1..16000 (default 300). Larger cells remain in the index;
    use length()/substr() with file_id and a stable row key for longer values.
    """
    if version_code <= 0 or version_code > 9999999999 or operation not in {"inventory", "audit", "decompile", "query", "decode", "string_refs", "info", "multipath_audit", "regenerate_ai", "source_check"} or len(argument) > 4096:
        raise ToolError("Invalid bounded operation parameters")
    if not 1 <= max_cell_chars <= 16000 or (operation != "query" and max_cell_chars != 300):
        raise ToolError("max_cell_chars must be 1..16000 and only varies for query")
    if source_mode not in {"auto", "worktree", "published", "historical"}:
        raise ToolError("Unsupported source_mode")
    if source_mode != "auto" and operation not in {"multipath_audit", "regenerate_ai", "source_check"}:
        raise ToolError("source_mode applies only to complete analysis")
    if operation in {"multipath_audit", "source_check"} and source_mode == "historical":
        raise ToolError("New analysis cannot silently use historical source")
    request = uuid.uuid4().hex
    inputs = {"request_id": request, "version_code": str(version_code),
              "operation": operation, "argument": argument}
    # Omit the default so an older workflow can still serve legacy clients.
    if max_cell_chars != 300:
        inputs["max_cell_chars"] = str(max_cell_chars)
    binding = None
    if operation in {"multipath_audit", "source_check"} or operation == "regenerate_ai" and source_mode not in {"auto", "historical"}:
        import snapshot_transport
        try:
            binding = snapshot_transport.prepare(hostlab.ROOT, gh, mode=source_mode)
        except Exception:
            raise ToolError("Source snapshot preparation failed; analysis was not dispatched") from None
        inputs["module_source"] = json.dumps(binding, separators=(",", ":"), sort_keys=True)
    record_path = hostlab.STATE / "remote-requests" / (request + ".json")
    queued_at = time.time()
    record = {
        "request_id": request, "version_code": version_code, "operation": operation,
        "source_mode": source_mode, "module_source": binding, "status": "dispatch_unknown",
        "created_at": queued_at, "queued_at": queued_at}
    hostlab.write_json(record_path, record)
    import remote_dispatch
    dispatched = remote_dispatch.dispatch(REPO, WORKFLOW, inputs, gh)
    record.update({key: value for key, value in dispatched.items() if key not in {"dispatched", "next_action"}})
    hostlab.write_json(record_path, record)
    return json.dumps({**record, "repository": REPO, "dispatched": dispatched["dispatched"],
                       **({"next_action": dispatched["next_action"]} if "next_action" in dispatched else {})})


@mcp.tool()
def job_status(request_id: str) -> str:
    """Get queue/running/completion state for a submitted request. Does not wait."""
    started = time.monotonic()
    run = lookup(request_id)
    if run is None:
        return json.dumps({"status": "dispatch_pending", "request_id": request_id,
                           "lookup_elapsed_ms": (time.monotonic()-started)*1000})
    import remote_schedule
    receipt = remote_schedule.observe(request_id, run)
    if receipt is None:
        journal = hostlab.STATE / "remote-requests" / (request_id + ".json")
        try:
            if journal.is_file() and journal.stat().st_size <= 1024 * 1024:
                receipt = remote_schedule.reconcile(json.loads(journal.read_text(encoding="utf-8")), run)
        except (OSError, ValueError):
            pass
    result = {k: run[k] for k in ("id", "status", "conclusion", "html_url", "head_sha") if k in run}
    if receipt is not None:
        result.update(status=remote_schedule.public_status(receipt), conclusion=receipt.get("conclusion"),
            state_uncertain=receipt.get("state_uncertain", False),
            stale_observation_ignored=receipt.get("stale_observation_ignored", False))
        for key in ("queued_at", "dispatch", "run_attempt", "run_updated_at"):
            if key in receipt:
                result[key] = receipt[key]
    result.update(request_id=request_id, lookup_elapsed_ms=(time.monotonic()-started)*1000)
    return json.dumps(result)


@mcp.tool()
def list_jobs() -> str:
    """List the latest ten analysis runs."""
    return json.dumps([{k: r[k] for k in ("id", "display_title", "status", "conclusion", "html_url")} for r in runs()[:10]])


@mcp.tool()
def job_result(request_id: str, result_offset: int = 0, sample_index: int = -1,
               page_chars: int = RESULT_PAGE_CHARS, result_file: str = "") -> str:
    """Download result artifacts and return bounded text plus local file paths. No APK or DEX.

    Pages default to 32000 Unicode characters; page_chars accepts 1024..128000.
    Combined previews are capped at three pages. result.txt (durable report: report.md)
    is selected by default. Set result_file to job.json, summary.json, or another
    returned text file's exact relative path to page metadata. file_pages lists cursors.
    Pass result_page.next_offset back as result_offset, retaining result_file, until null. Reading pages
    reuses the downloaded artifact; it does not submit another Actions analysis job.
    Grouped jobs return a bounded group receipt and all file paths by default.
    Set sample_index=0..11 to inspect/page a specific member, including failed members.
    """
    if type(result_offset) is not int or not 0 <= result_offset <= 2147483647:
        raise ToolError("result_offset must be 0..2147483647")
    if type(sample_index) is not int or not -1 <= sample_index <= 11:
        raise ToolError("sample_index must be -1..11")
    if type(page_chars) is not int or not 1024 <= page_chars <= MAX_RESULT_PAGE_CHARS:
        raise ToolError("page_chars must be 1024..128000")
    if not isinstance(result_file, str):
        raise ToolError("result_file must name a returned text file")
    result_file = result_file.replace("\\", "/")
    if result_file and (len(result_file) > 4096 or re.match(r"^[A-Za-z]:", result_file)
                        or any(part in {"", ".", ".."} for part in result_file.split("/"))
                        or result_file.split("/")[-1] not in PAGEABLE_FILES):
        raise ToolError("result_file must be a returned text file path (up to 4096 characters, no traversal)")
    durable=repository_report(request_id,result_offset,page_chars,result_file)
    if durable:
        if sample_index != -1:
            raise ToolError("sample_index applies only to grouped jobs")
        return json.dumps(durable,ensure_ascii=False)
    run = lookup(request_id)
    if run is None or run["status"] != "completed":
        raise ToolError("Job has not completed")
    import remote_artifacts
    try:
        collected = remote_artifacts.get(REPO, request_id, run, gh)
    except (ValueError, OSError) as exc:
        raise ToolError(str(exc) if isinstance(exc, remote_artifacts.ArtifactError) else "artifact_collection_failed") from None
    files = sorted((Path(p) for p in collected["files"]),
                   key=lambda p: (p.name != "result.txt", str(p)))
    out = Path(collected["root"])
    groups = [p for p in files if p.name == "group.json"]
    if groups:
        if len(groups) != 1:
            raise ToolError("Ambiguous runner group receipt")
        if sample_index == -1:
            return json.dumps({"run": run["html_url"], "files": [str(p) for p in files],
                **result_previews(groups,out,result_offset,page_chars,result_file,"group.json"),
                "task_summary": task_summary(files,out),
                "grouped": True, "next_action": "job_result(request_id, sample_index=0..11) or version_matrix_result",
                "collection": {key:collected[key] for key in ("cache_hit", "artifact", "integrity", "elapsed_ms", "run_attempt")}}, ensure_ascii=False)
        member = groups[0].parent / "samples" / str(sample_index)
        files = [p for p in files if p.parent == member and p.name in {"job.json", "result.txt", "summary.md"}]
        if not files:
            raise ToolError("Runner group member has no saved output; inspect the group receipt")
    elif sample_index != -1:
        raise ToolError("sample_index applies only to grouped jobs")
    rendered = result_previews(files,out,result_offset,page_chars,result_file)
    summaries = [p for p in files if p.name == "priority-summary.json"]
    freshness = source_freshness(json.loads(summaries[0].read_text(encoding="utf-8"))) if len(summaries) == 1 else None
    return json.dumps({"run": run["html_url"], "files": [str(p) for p in files],
                       **rendered, "source_freshness": freshness,
                       "task_summary": task_summary(files,out),
                       "collection": {key:collected[key] for key in ("cache_hit", "artifact", "integrity", "elapsed_ms", "run_attempt")}}, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run(transport="stdio")
