"""Versioned, bounded analysis requests and deterministic backend planning. No I/O."""
from __future__ import annotations

import hashlib
import json
import re

SCHEMA = 1
MAX_TASKS = 16
MAX_REQUEST_BYTES = 30000
BACKENDS = {"auto", "sqlite", "dexsql"}
OPERATIONS = {"query", "locate", "refs", "decode", "info"}


def integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be {low}..{high}")
    return value


def text(value, maximum, name):
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValueError("invalid " + name)
    return value


def validate(request):
    if not isinstance(request, dict) or set(request) - {"schema", "backend", "timeout_seconds", "threads", "tasks", "resume"}:
        raise ValueError("unsupported analysis request fields")
    if type(request.get("schema", SCHEMA)) is not int or request.get("schema", SCHEMA) != SCHEMA:
        raise ValueError("unsupported analysis schema")
    if request.get("backend", "auto") not in BACKENDS:
        raise ValueError("unsupported backend")
    tasks = request.get("tasks")
    if not isinstance(tasks, list) or not 1 <= len(tasks) <= MAX_TASKS:
        raise ValueError("analysis needs 1..16 tasks")
    normalized = {"schema": SCHEMA, "backend": request.get("backend", "auto"),
                  "timeout_seconds": integer(request.get("timeout_seconds", 180), 1, 600, "timeout_seconds"),
                  "threads": integer(request.get("threads", 2), 1, 6, "threads"), "tasks": []}
    ids = set()
    if "resume" in request:
        resume = request["resume"]
        if (not isinstance(resume, dict) or not {"run_id", "attempt", "request_id"} <= set(resume)
                or set(resume)-{"run_id", "attempt", "request_id", "sample_index"}):
            raise ValueError("resume needs run_id, attempt, request_id and optional sample_index")
        if not isinstance(resume["request_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", resume["request_id"]):
            raise ValueError("invalid resume request_id")
        normalized["resume"] = {"run_id": integer(resume["run_id"], 1, 10**15, "resume run_id"),
            "attempt": integer(resume["attempt"], 1, 1000, "resume attempt"), "request_id": resume["request_id"]}
        if "sample_index" in resume:
            normalized["resume"]["sample_index"] = integer(resume["sample_index"], 0, 11, "resume sample_index")
    fields = {"query": {"sql", "dialect", "offset", "pagination"}, "locate": {"kind", "name", "owner"},
              "refs": {"kind", "target", "detail"}, "decode": {"method", "file_id"}, "info": set()}
    for task in tasks:
        if not isinstance(task, dict) or task.get("operation") not in OPERATIONS:
            raise ValueError("unsupported analysis operation")
        op = task["operation"]
        if set(task) - ({"id", "operation", "limit"} | fields[op]):
            raise ValueError("unsupported task fields")
        name = task.get("id")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", name) or name in ids:
            raise ValueError("task IDs must be unique bounded identifiers")
        ids.add(name)
        item = {"id": name, "operation": op, "limit": integer(task.get("limit", 100), 1, 1000, "limit")}
        if op == "query":
            item["sql"] = text(task.get("sql"), 12000, "SQL")
            if not re.match(r"(?is)^\s*(select|with)\b", item["sql"]):
                raise ValueError("query accepts SELECT/WITH only")
            item["dialect"] = task.get("dialect", "sqlite")
            if item["dialect"] not in {"sqlite", "dexsql"}:
                raise ValueError("query dialect must be sqlite or dexsql")
            item["offset"] = integer(task.get("offset", 0), 0, 99000, "offset")
            if item["dialect"] == "sqlite" and item["offset"]:
                raise ValueError("SQLite query paging must be explicit in its SQL")
            if normalized["backend"] != "auto" and normalized["backend"] != item["dialect"]:
                raise ValueError("explicit SQL dialect cannot be changed by backend selection")
            if "pagination" in task:
                paging = task["pagination"]
                if item["dialect"] != "dexsql" or not isinstance(paging, dict) or set(paging) - {"max_pages", "max_rows", "max_bytes"}:
                    raise ValueError("pagination applies only to DexSQL queries")
                limits = {"max_pages": (1, 32), "max_rows": (1, 10000), "max_bytes": (1024, 1024 * 1024)}
                item["pagination"] = {key: integer(value, *limits[key], key) for key, value in paging.items()}
        elif op == "locate":
            item["kind"] = task.get("kind", "method")
            if item["kind"] not in {"class", "method", "field"}:
                raise ValueError("unsupported locate kind")
            item["name"] = text(task.get("name"), 1024, "name")
            if task.get("owner") is not None:
                item["owner"] = text(task["owner"], 1024, "owner")
        elif op == "refs":
            item["kind"] = task.get("kind", "string")
            item["detail"] = task.get("detail", "methods")
            item["target"] = text(task.get("target"), 4096, "target")
            if item["kind"] not in {"method", "field", "string", "type"} or item["detail"] not in {"methods", "sites"}:
                raise ValueError("unsupported reference kind/detail")
            if item["kind"] == "method" and not re.fullmatch(r"L[^;]+;->[^\s(]+\([^\s]*\)[^\s]+", item["target"]):
                raise ValueError("method reference needs a full DEX descriptor")
            if item["kind"] == "field" and not re.fullmatch(r"L[^;]+;->[^\s:]+:[^\s]+", item["target"]):
                raise ValueError("field reference needs a full DEX descriptor")
            if item["kind"] == "type" and not re.fullmatch(r"(?:\[)*(?:L[^;]+;|[ZBSCIJFD])", item["target"]):
                raise ValueError("type reference needs a DEX descriptor")
            if item["detail"] == "sites" and normalized["backend"] == "dexsql":
                raise ValueError("DexSQL cannot supply legacy offset/op reference sites")
        elif op == "decode":
            item["method"] = text(task.get("method"), 4096, "method")
            if not re.fullmatch(r"L[^;]+;->[^\s(]+\([^\s]*\)[^\s]+", item["method"]):
                raise ValueError("decode needs a full DEX method descriptor")
            if "file_id" in task:
                item["file_id"] = integer(task["file_id"], 0, 1000000, "file_id")
                if normalized["backend"] == "sqlite":
                    raise ValueError("legacy SQLite decode cannot select a file_id")
        normalized["tasks"].append(item)
    if len(json.dumps(normalized, ensure_ascii=False).encode()) > MAX_REQUEST_BYTES:
        raise ValueError("analysis request exceeds 30000 UTF-8 bytes")
    return normalized


def fingerprint(request):
    value = json.dumps(validate(request), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(value.encode()).hexdigest()


def plan(request, *, dexsql_available=True, sqlite_cache_hit=False):
    request = validate(request)
    tasks = []
    for task in request["tasks"]:
        op = task["operation"]
        if op == "query":
            backend, reason = task["dialect"], "explicit_sql_dialect"
        elif op == "refs" and task["detail"] == "sites":
            backend, reason = "sqlite", "preserve_reference_offsets_and_opcodes"
        elif request["backend"] != "auto":
            backend, reason = request["backend"], "explicit_backend"
        elif op == "decode" and "file_id" in task:
            backend, reason = "dexsql", "explicit_dexsql_file_coordinates"
        elif op == "locate" and sqlite_cache_hit:
            backend, reason = "sqlite", "reuse_existing_structural_index"
        else:
            backend, reason = "dexsql", "reuse_native_references_and_preparation"
        fallback = None
        if backend == "dexsql" and not dexsql_available:
            if request["backend"] == "auto" and op != "query" and "file_id" not in task:
                backend, reason, fallback = "sqlite", "dexsql_unavailable_equivalent_legacy_operation", "dexsql"
            else:
                raise ValueError("requested pinned DexSQL backend is unavailable")
        tasks.append({"id": task["id"], "backend": backend, "reason": reason, "fallback_from": fallback})
    # Avoid a second session just for warm metadata when native work already needs preparation.
    required_native = any(t["backend"] == "dexsql" for t in tasks)
    required_legacy = any(t["backend"] == "sqlite" and t["reason"] != "reuse_existing_structural_index" for t in tasks)
    if required_native and not required_legacy:
        for task in tasks:
            if task["reason"] == "reuse_existing_structural_index":
                task.update(backend="dexsql", reason="share_already_required_native_session")
    groups = [{"backend": b, "task_ids": [t["id"] for t in tasks if t["backend"] == b]}
              for b in ("sqlite", "dexsql") if any(t["backend"] == b for t in tasks)]
    return {"schema": SCHEMA, "request_sha256": fingerprint(request), "tasks": tasks, "groups": groups,
            "dataset_opens": len(groups), "execution": "one_sequential_session_per_backend",
            "threads": request["threads"], "timeout_seconds": request["timeout_seconds"],
            "raw_sql_rewritten": False, "scope": "offline_static_only"}


def quote(value):
    return "'" + value.replace("'", "''") + "'"


def locate_sql(task, backend):
    name = quote(task["name"])
    owner = task.get("owner")
    if task["kind"] == "class":
        return f"SELECT file_id,descriptor FROM classes WHERE descriptor={name} ORDER BY file_id"
    if backend == "sqlite":
        kind = task["kind"]
        signature = "class||'->'||name||proto" if kind == "method" else "class||'->'||name||':'||type"
        table = "methods" if kind == "method" else "fields"
        where = " AND class=" + quote(owner) if owner else ""
        return f"SELECT file_id,{signature} AS descriptor FROM {table} WHERE name={name}{where} ORDER BY file_id,descriptor"
    prefix = "method" if task["kind"] == "method" else "field"
    where = " AND class_descriptor=" + quote(owner) if owner else ""
    return (f"SELECT file_id,{prefix}_descriptor AS descriptor FROM class_{prefix}s "
            f"WHERE {prefix}_name={name}{where} ORDER BY file_id,descriptor")


def refs_sql(task):
    table, column = {"string": ("method_strings", "value"), "method": ("method_calls", "callee"),
                     "field": ("method_field_accesses", "field"), "type": ("method_used_types", "type_descriptor")}[task["kind"]]
    return (f"SELECT file_id,method AS descriptor FROM {table} WHERE {column}={quote(task['target'])} "
            "ORDER BY file_id,method_idx")
