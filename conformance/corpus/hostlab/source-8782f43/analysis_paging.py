"""Bounded DexSQL query continuation. SQL text and row multiplicity are preserved."""
from __future__ import annotations

import copy
import hashlib
import json
import re

DEFAULTS = {"max_pages": 8, "max_rows": 1000, "max_bytes": 1024 * 1024}


class PageError(ValueError):
    pass


def size(value):
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))


def continuation_reason(sql):
    # Read SQL tokens without rewriting SQL or treating quoted text/subquery ORDER BY as outer ordering.
    matches = re.finditer(r"--[^\n]*|/\*[\s\S]*?\*/|'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|`(?:[^`]|``)*`|\[[^\]]*\]|[()]|[A-Za-z_][A-Za-z_0-9]*", sql)
    tokens = [m[0] for m in matches if not m[0].startswith(("--", "/*", "'"))]
    depth, outer = 0, []
    for index, token in enumerate(tokens):
        quoted = token.startswith(('"', "`", "["))
        word = token[1:-1].upper() if quoted else token.upper()
        if (word in {"RANDOM", "RANDOMBLOB", "UUID", "NOW"} and tokens[index+1:index+2] == ["("]
                or not quoted and word in {"CURRENT_TIMESTAMP", "CURRENT_DATE", "CURRENT_TIME"}):
            return "query_volatile_order_or_values"
        if quoted:
            continue
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
        else:
            if depth == 0:
                outer.append(word)
    if not any(a == "ORDER" and b == "BY" for a, b in zip(outer, outer[1:])):
        return "query_requires_stable_outer_order"
    return None


def statement(result):
    try:
        raw = result["typed_result"]
        if len(raw["statements"]) != 1:
            raise PageError("query_statement_count_changed")
        item = raw["statements"][0]
        columns = item["columns"]
        rows = item["rows"]
        if (item["kind"] != "query" or not isinstance(rows, list) or not isinstance(columns, list)
                or result["columns"] != [c["name"] for c in columns]
                or any(len(row) != len(columns) for row in rows)
                or result["rows"] != [[cell["value"] for cell in row] for row in rows]):
            raise PageError("query_rows_or_schema_inconsistent")
        offset, cursor, total = item["offset"], item["next_offset"], item.get("total_rows")
        if type(offset) is not int or not 0 <= offset <= 100000:
            raise PageError("invalid_query_offset")
        if type(item["truncated"]) is not bool:
            raise PageError("invalid_query_truncation")
        if total is not None and (type(total) is not int or total < 0 or rows and total < offset + len(rows)):
            raise PageError("invalid_query_total")
        if cursor is not None and (type(cursor) is not int or cursor != offset + len(rows) or cursor <= offset or cursor > 100000):
            raise PageError("query_cursor_did_not_advance")
        if cursor is not None and total is not None and cursor >= total:
            raise PageError("query_cursor_beyond_total")
        if cursor is None and not item["truncated"] and total is not None and offset + len(rows) != total and not (not rows and offset >= total):
            raise PageError("query_terminal_count_mismatch")
        if result["partial"] != bool(item["truncated"] or cursor is not None):
            raise PageError("query_partial_flag_inconsistent")
        return item
    except (KeyError, TypeError, IndexError) as exc:
        raise PageError("invalid_query_page") from exc


def sql_matches(item, sql):
    # DexSQL abbreviates SQL metadata, never cells. The full request remains hash-bound separately.
    return item.get("sql_truncated") is True or item["sql"] == sql


class QueryPages:
    def __init__(self, task, seed=None, *, remaining_bytes=1024 * 1024):
        self.task = task
        self.limits = {**DEFAULTS, **task.get("pagination", {})}
        self.limits["max_bytes"] = min(self.limits["max_bytes"], remaining_bytes)
        self.result = copy.deepcopy(seed) if seed is not None else None
        self.pages = 0
        self.initial_pages = 0
        self.reused_rows = 0
        self.fetched_rows = 0
        self.requests = []
        self.reason = None
        self.page_limit_cap = task["limit"]
        self.oversized_attempts = 0
        if self.result is not None:
            self.page_limit_cap = self.result.get("pagination", {}).get("page_limit_cap", task["limit"])
            if type(self.page_limit_cap) is not int or not 1 <= self.page_limit_cap <= task["limit"]:
                raise PageError("invalid_checkpoint_page_limit")
        if self.result is not None and "typed_result" not in self.result:
            p = self.result.get("pagination", {})
            if (self.result.get("rows") != [] or self.result.get("columns") != [] or self.result.get("partial") is not True
                    or p.get("pages") != 0 or p.get("rows") != 0 or p.get("next_offset") != task["offset"]):
                raise PageError("invalid_empty_checkpoint_page")
            self.result = None  # No page was admitted under the previous exhausted batch budget.
        if self.result is not None:
            item = statement(self.result)
            if item["offset"] != task["offset"] or not sql_matches(item, task["sql"]):
                raise PageError("checkpoint_query_identity_mismatch")
            previous = self.result.get("pagination", {})
            self.pages = previous.get("pages", 1)
            if type(self.pages) is not int or not 1 <= self.pages <= len(self.result["rows"]) + 1:
                raise PageError("invalid_checkpoint_page_count")
            self.initial_pages = self.pages
            self.reused_rows = len(self.result["rows"])
            if self.reused_rows > self.limits["max_rows"] or size(self.result) > self.limits["max_bytes"]:
                raise PageError("checkpoint_exceeds_query_budget")
            if size(self.stopped("resume_pending")) + 128 > self.limits["max_bytes"]:
                raise PageError("checkpoint_metadata_exceeds_query_budget")

    @property
    def cursor(self):
        return statement(self.result)["next_offset"] if self.result is not None else self.task["offset"]

    def next_limit(self):
        rows = len(self.result["rows"]) if self.result is not None else 0
        if self.pages - self.initial_pages >= self.limits["max_pages"]:
            self.reason = "page_budget"
            return 0
        remaining = self.limits["max_rows"] - rows
        if remaining <= 0:
            self.reason = "row_budget"
            return 0
        count = min(self.page_limit_cap, remaining)
        if self.cursor is None:
            self.reason = "backend_truncated_without_cursor" if self.result["partial"] else "complete"
            return 0
        count = min(count, 100000 - self.cursor)
        if count <= 0:
            self.reason = "backend_offset_budget"
            return 0
        if self.result is not None:
            previous = statement(self.result)
            if previous["next_offset"] is None:
                self.reason = "backend_truncated_without_cursor" if previous["truncated"] else "complete"
                return 0
            if reason := continuation_reason(self.task["sql"]):
                self.reason = reason
                return 0
            if previous.get("total_rows") is not None:
                count = min(count, previous["total_rows"] - previous["next_offset"])
        return count

    def shrink_oversized_page(self, requested):
        if requested <= 1:
            return False
        self.page_limit_cap = max(1, requested//2)
        self.oversized_attempts += 1
        return True

    def admit(self, page, requested_limit):
        current = statement(page)
        if current["offset"] != self.cursor or not sql_matches(current, self.task["sql"]) or len(page["rows"]) > requested_limit:
            raise PageError("query_page_identity_or_limit_mismatch")
        merged = copy.deepcopy(page)
        if self.result is not None:
            previous = statement(self.result)
            if (current["columns"] != previous["columns"] or current.get("total_rows") != previous.get("total_rows")
                    or current["sql"] != previous["sql"] or current.get("sql_truncated", False) != previous.get("sql_truncated", False)):
                raise PageError("query_schema_or_total_changed")
            merged = copy.deepcopy(self.result)
            item = merged["typed_result"]["statements"][0]
            item["rows"] += copy.deepcopy(current["rows"])
            for key in ("next_offset", "truncated"):
                item[key] = current[key]
            item["execute_ms"] = previous.get("execute_ms", 0) + current.get("execute_ms", 0)
            merged["rows"] += copy.deepcopy(page["rows"])
            merged["partial"] = page["partial"]
            diagnostics = merged["typed_result"].setdefault("diagnostics", [])
            seen = {json.dumps(d, sort_keys=True, ensure_ascii=False) for d in diagnostics}
            for diagnostic in page["typed_result"].get("diagnostics", []):
                key = json.dumps(diagnostic, sort_keys=True, ensure_ascii=False)
                if key not in seen:
                    diagnostics.append(copy.deepcopy(diagnostic))
                    seen.add(key)
            # The merged statement describes the whole admitted range, not the last page.
        self.pages += 1
        self.fetched_rows += len(page["rows"])
        self.requests.append({"offset": current["offset"], "limit": requested_limit,
                              "rows": len(page["rows"]), "next_offset": current["next_offset"]})
        self.reason = "backend_truncated_without_cursor" if current["next_offset"] is None and current["truncated"] else (
            "complete" if not page["partial"] else "more_rows")
        self.decorate(merged)
        # Reserve bounded space for a later stop reason without exceeding the admitted byte budget.
        if size(merged) + 128 > self.limits["max_bytes"]:
            self.pages -= 1
            self.fetched_rows -= len(page["rows"])
            self.requests.pop()
            self.reason = "byte_budget"
            return False
        self.result = merged
        return True

    def decorate(self, result):
        item = result["typed_result"]["statements"][0]
        result["pagination"] = {"pages": self.pages, "pages_this_run": self.pages-self.initial_pages, "rows": len(result["rows"]),
            "page_limit_cap": self.page_limit_cap, "oversized_page_attempts_this_run": self.oversized_attempts,
            "reused_rows": self.reused_rows, "fetched_rows": self.fetched_rows,
            "start_offset": self.task["offset"], "next_offset": item["next_offset"],
            "total_rows": item.get("total_rows"), "limits": self.limits, "stop_reason": self.reason,
            "requests_this_run": list(self.requests),
            "sql_sha256": hashlib.sha256(self.task["sql"].encode("utf-8")).hexdigest()}

    def stopped(self, reason=None):
        if reason:
            self.reason = reason
        if self.result is None:
            return {"columns": [], "rows": [], "partial": True, "pagination": {
                "pages": 0, "rows": 0, "reused_rows": 0, "fetched_rows": 0,
                "page_limit_cap": self.page_limit_cap, "oversized_page_attempts_this_run": self.oversized_attempts,
                "next_offset": self.task["offset"], "total_rows": None, "limits": self.limits,
                "stop_reason": self.reason}}
        result = copy.deepcopy(self.result)
        self.decorate(result)
        return result
