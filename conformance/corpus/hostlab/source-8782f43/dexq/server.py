"""dexq-mcp：用 androguard 4.1.4 建 SQLite 索引的 DEX/APK 查询 MCP（stdio）。

定位：宿主 APK（几十个 dex、近 30 万个类）的"结构层"快查——按名字/字符串/签名找类、方法、字段，
查引用，读 smali。它不做反编译成 Java；要读伪 Java 再退回 jadx，且结论仍须运行期确认。

设计取舍：
- 索引一次、跨会话复用：按 (路径, 大小, mtime) 哈希落盘到 cache/*.sqlite，命中即秒开。
- 索引在多进程里建（androguard 是纯 Python），主进程只负责入库。
- SQL 只读：mode=ro + query_only + 只放行 SELECT/WITH + 超时。
- 路径白名单 DEXQ_ROOTS（os.pathsep 分隔），默认只有启动目录。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
import zipfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from loguru import logger

logger.remove()

import dexq_workers as W  # noqa: E402  必须在 logger.remove() 之后
from mcp.server.mcpserver import MCPServer  # noqa: E402
from mcp.server.mcpserver.exceptions import ToolError  # noqa: E402

ROOT = Path(__file__).resolve().parent
CACHE_DIR = Path(os.environ.get("DEXQ_CACHE_DIR", str(ROOT / "cache"))).resolve()
SCHEMA_VERSION = 1
QUERY_TIMEOUT_S = 60
MAX_CELL = 300
MAX_CELL_CHARS = 16000
MAX_QUERY_CHARS = 64000
ALLOWED_EXT = {".apk", ".dex", ".zip", ".jar"}

INSTRUCTIONS = """\
dexq: SQL over the structure of Android DEX/APK files (classes, methods, fields, strings, references)
plus smali disassembly. It parses raw dex, so names are exactly what the runtime sees.

Prefer dexq over jadx / dexdump / ad-hoc scripts whenever you need to LOCATE things in an APK: find a
class/method/field by name or shape, find strings, find who calls/uses something, read one method's
smali, or compare versions. Use jadx only when you need readable pseudo-Java, and treat its output
(especially field names in multi-dex apps) as a hint, not evidence.

Workflow: open_dataset(inputs=[absolute apk path]) -> describe_tables -> query (SQL) -> decode / find_refs.
The first open of a large APK builds an on-disk index (minutes for a ~30-dex host); later opens are instant.
Duplicate class names across dex files are real: always keep file_id in your SELECTs.
query defaults to 300 escaped chars per cell. A truncation footer means the tail was NOT observed:
request max_cell_chars (up to 16000), or page a long value with length()/substr() and a stable key.
"""

mcp = MCPServer(name="dexq", instructions=INSTRUCTIONS)

_datasets: dict[str, dict] = {}
_dex_cache: dict[tuple, object] = {}  # (src, member) -> DEX，最多 2 个，decode 用


# ---------------------------------------------------------------- 路径 / 输入

def _roots() -> list[Path]:
    raw = os.environ.get("DEXQ_ROOTS", "")
    roots = [Path(p).expanduser().resolve() for p in raw.split(os.pathsep) if p.strip()]
    return roots or [Path.cwd().resolve()]


def _check_path(path: str) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise ToolError(f"file not found: {p}")
    if p.suffix.lower() not in ALLOWED_EXT:
        raise ToolError(f"unsupported extension {p.suffix!r}; allowed: {sorted(ALLOWED_EXT)}")
    for root in _roots():
        try:
            p.relative_to(root)
            return p
        except ValueError:
            continue
    raise ToolError(f"path not under allowed roots {[str(r) for r in _roots()]}: {p} "
                     "(set DEXQ_ROOTS)")


def _dex_members(p: Path) -> list[tuple[str, str | None, int]]:
    """[(源文件, zip 成员名或 None, 字节数)]，按 classes.dex、classes2.dex… 的自然顺序。"""
    if p.suffix.lower() == ".dex":
        return [(str(p), None, p.stat().st_size)]
    with zipfile.ZipFile(p) as zf:
        infos = [i for i in zf.infolist() if re.fullmatch(r"classes\d*\.dex", i.filename)]
    if not infos:
        raise ToolError(f"no classes*.dex in {p}")
    infos.sort(key=lambda i: int(re.sub(r"\D", "", i.filename) or "1"))
    return [(str(p), i.filename, i.file_size) for i in infos]


def _cache_key(paths: list[Path]) -> str:
    parts = [(str(p), p.stat().st_size, p.stat().st_mtime_ns) for p in paths]
    return hashlib.sha1(json.dumps([SCHEMA_VERSION, parts]).encode()).hexdigest()[:16]


# ---------------------------------------------------------------- 建索引

_DDL = """
CREATE TABLE dex_files(file_id INTEGER PRIMARY KEY, source TEXT, member TEXT, size INTEGER,
    n_classes INTEGER, n_method_ids INTEGER, n_field_ids INTEGER, n_strings INTEGER);
CREATE TABLE classes(file_id INTEGER, descriptor TEXT, access TEXT, superclass TEXT,
    interfaces TEXT, source_file TEXT);
CREATE TABLE methods(file_id INTEGER, method_idx INTEGER, class TEXT, name TEXT, proto TEXT,
    access TEXT, code_size INTEGER);
CREATE TABLE fields(file_id INTEGER, class TEXT, name TEXT, type TEXT, access TEXT);
CREATE TABLE method_ids(file_id INTEGER, method_idx INTEGER, class TEXT, name TEXT, proto TEXT);
CREATE TABLE field_ids(file_id INTEGER, field_idx INTEGER, class TEXT, name TEXT, type TEXT);
CREATE TABLE strings(file_id INTEGER, string_idx INTEGER, value TEXT);
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
"""
_INDEXES = """
CREATE INDEX i_classes_desc ON classes(descriptor);
CREATE INDEX i_classes_super ON classes(superclass);
CREATE INDEX i_methods_cls ON methods(class, name);
CREATE INDEX i_methods_name ON methods(name);
CREATE INDEX i_fields_cls ON fields(class, name);
CREATE INDEX i_mids ON method_ids(class, name);
CREATE INDEX i_fids ON field_ids(class, name);
CREATE INDEX i_str_val ON strings(value);
CREATE INDEX i_str_idx ON strings(file_id, string_idx);
"""
_INSERTS = {
    "classes": "INSERT INTO classes VALUES (?,?,?,?,?,?)",
    "methods": "INSERT INTO methods VALUES (?,?,?,?,?,?,?)",
    "fields": "INSERT INTO fields VALUES (?,?,?,?,?)",
    "method_ids": "INSERT INTO method_ids VALUES (?,?,?,?,?)",
    "field_ids": "INSERT INTO field_ids VALUES (?,?,?,?,?)",
    "strings": "INSERT INTO strings VALUES (?,?,?)",
}


def _workers() -> int:
    env = os.environ.get("DEXQ_WORKERS")
    if env:
        return max(1, int(env))
    return max(1, min(6, (os.cpu_count() or 2) // 2))


def _build(paths: list[Path], db_path: Path) -> dict:
    members = [m for p in paths for m in _dex_members(p)]
    jobs = [(src, member, i) for i, (src, member, _size) in enumerate(members)]
    # 大的先跑，避免最后一个大 dex 拖尾（file_id 仍按自然顺序，入库时不受影响）
    order = [jobs[i] for i in sorted(range(len(members)), key=lambda i: -members[i][2])]
    started = time.time()
    tmp = db_path.with_suffix(".sqlite.tmp")
    if tmp.exists():
        tmp.unlink()
    conn = sqlite3.connect(tmp)
    conn.executescript("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;")
    conn.executescript(_DDL)
    with ProcessPoolExecutor(max_workers=_workers(), initializer=W.init_worker) as pool:
        for res in pool.map(W.extract, order):
            conn.execute("INSERT INTO dex_files VALUES (?,?,?,?,?,?,?,?)", res["dex"])
            for table, sql in _INSERTS.items():
                conn.executemany(sql, res[table])
    conn.executescript(_INDEXES)
    seconds = round(time.time() - started, 1)
    conn.executemany("INSERT INTO meta VALUES (?,?)", [
        ("schema_version", str(SCHEMA_VERSION)),
        ("inputs", json.dumps([str(p) for p in paths])),
        ("build_seconds", str(seconds)),
        ("built_at", time.strftime("%Y-%m-%d %H:%M:%S")),
    ])
    conn.commit()
    conn.close()
    os.replace(tmp, db_path)
    return {"build_seconds": seconds, "dex_files": len(members)}


def _ro(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    conn.execute("PRAGMA query_only=1")
    return conn


def _dataset(dataset_id: str) -> dict:
    ds = _datasets.get(dataset_id)
    if ds is None:
        raise ToolError(f"unknown dataset_id {dataset_id!r}; call open_dataset "
                         "(a server restart drops ids, the on-disk index stays)")
    return ds


# ---------------------------------------------------------------- 工具

@mcp.tool()
def open_dataset(inputs: list[str], rebuild: bool = False) -> str:
    """Open one or more local .apk/.dex/.zip/.jar files (absolute paths) as one dataset.

    The first open of a file builds an on-disk SQLite index (a ~30-dex host APK takes minutes;
    small APKs seconds). Later opens of the same unchanged file are instant. Several inputs form one
    dataset; file_id identifies each dex across them. rebuild=true forces a fresh index.
    """
    if not inputs:
        raise ToolError("inputs must not be empty")
    paths = [_check_path(p) for p in inputs]
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = _cache_key(paths)
    db_path = CACHE_DIR / f"{key}.sqlite"
    hit = db_path.exists() and not rebuild
    info = {"cache": "hit"} if hit else {"cache": "built", **_build(paths, db_path)}
    dataset_id = f"dataset-{len(_datasets) + 1}-{uuid.uuid4().hex[:4]}"
    _datasets[dataset_id] = {"db": str(db_path), "inputs": [str(p) for p in paths]}
    conn = _ro(str(db_path))
    try:
        files = conn.execute(
            "SELECT file_id, member, size, n_classes, n_method_ids, n_strings FROM dex_files "
            "ORDER BY file_id").fetchall()
        totals = conn.execute("SELECT (SELECT count(*) FROM classes), (SELECT count(*) FROM methods), "
                              "(SELECT count(*) FROM fields), (SELECT count(*) FROM strings)").fetchone()
    finally:
        conn.close()
    return json.dumps({
        "dataset_id": dataset_id, **info, "inputs": _datasets[dataset_id]["inputs"],
        "totals": dict(zip(["classes", "defined_methods", "defined_fields", "strings"], totals)),
        "dex_files": [dict(zip(["file_id", "member", "bytes", "classes", "method_ids", "strings"], f))
                      for f in files],
    }, ensure_ascii=False)


@mcp.tool()
def list_datasets() -> str:
    """List datasets opened in this server session."""
    return json.dumps({k: v["inputs"] for k, v in _datasets.items()}, ensure_ascii=False)


@mcp.tool()
def close_dataset(dataset_id: str) -> str:
    """Forget a dataset id. The on-disk index is kept for the next open."""
    return json.dumps({"closed": _datasets.pop(dataset_id, None) is not None})


@mcp.tool()
def describe_tables() -> str:
    """Schema of the index plus example queries. Call this before writing SQL."""
    return """\
Tables (every row carries file_id = which dex; the same class name can exist in several dex files):
  dex_files(file_id, source, member, size, n_classes, n_method_ids, n_field_ids, n_strings)
  classes(file_id, descriptor, access, superclass, interfaces, source_file)      -- descriptor 'Lcom/x/Y;'
  methods(file_id, method_idx, class, name, proto, access, code_size)             -- DEFINED methods; proto '(I)V'; code_size 0 = abstract/native
  fields(file_id, class, name, type, access)                                      -- DEFINED fields
  method_ids(file_id, method_idx, class, name, proto)                             -- every method REFERENCED (incl. framework)
  field_ids(file_id, field_idx, class, name, type)
  strings(file_id, string_idx, value)                                             -- the dex string pool
Signatures: method 'Lcom/x/Y;->name(I)V'  field 'Lcom/x/Y;->name:I'  (no spaces in protos).

Examples:
  SELECT file_id, descriptor FROM classes WHERE descriptor LIKE 'Lcom/bilibili/app/comment3/%' LIMIT 50;
  SELECT file_id, class, name, proto FROM methods WHERE name = 'getUrlsMap';
  SELECT m.class, m.name, m.proto FROM methods m JOIN classes c ON c.file_id=m.file_id AND c.descriptor=m.class
      WHERE c.superclass = 'Landroid/app/Application;';
  SELECT file_id, value FROM strings WHERE value LIKE '%disable_underline%';
  SELECT class, count(*) n FROM methods WHERE code_size > 0 GROUP BY class ORDER BY n DESC LIMIT 20;
Use find_refs for callers / string users, decode for smali.
"""


@mcp.tool()
def query(dataset_id: str, sql: str, limit: int = 100, max_cell_chars: int = MAX_CELL) -> str:
    """Run ONE read-only SELECT/WITH statement against the index. Output is a tab-separated table.

    limit caps the returned rows (max 1000). max_cell_chars is 1..16000 (default 300).
    Truncation is reported; for longer values SELECT length(value), substr(value,1,8000),
    then substr(value,8001,8000) with the same stable key and max_cell_chars=16000.
    Preview lengths count escaped characters; SQLite retains the full value.
    Output is bounded to 64000 chars at complete row boundaries. Times out after 60 s.
    """
    # 不能数分号：dex 描述符本身以 ';' 结尾（'Lcom/x/Y;'）。单语句由 sqlite3 自己保证——
    # 多语句会抛 ProgrammingError；只读连接（mode=ro + query_only）再兜住任何写操作。
    text = sql.strip().rstrip(";").strip()
    if not re.match(r"(?is)^(select|with)\b", text):
        raise ToolError("only SELECT / WITH statements are allowed")
    if not 1 <= max_cell_chars <= MAX_CELL_CHARS:
        raise ToolError(f"max_cell_chars must be 1..{MAX_CELL_CHARS}")
    limit = max(1, min(int(limit), 1000))
    conn = _ro(_dataset(dataset_id)["db"])
    deadline = time.time() + QUERY_TIMEOUT_S
    conn.set_progress_handler(lambda: 1 if time.time() > deadline else 0, 100000)
    try:
        cur = conn.execute(text)
        cols = [c[0] for c in cur.description]
        rows = cur.fetchmany(limit + 1)
    except sqlite3.Error as exc:  # OperationalError（语法/超时）与 ProgrammingError（多语句）
        raise ToolError(f"sql error: {exc}") from exc
    finally:
        conn.close()
    truncated = len(rows) > limit
    def escaped(v) -> str:
        s = "" if v is None else str(v)
        return s.replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")

    header = "\t".join(escaped(c) for c in cols)
    # Reserve space for the bounded footer; never return a partially rendered row.
    budget = MAX_QUERY_CHARS - 1024
    if len(header) > budget:
        raise ToolError("query header exceeds output budget; select fewer columns")
    lines = [header]
    used = len(header)
    returned = clipped = 0
    output_truncated = False
    for row in rows[:limit]:
        cells = [escaped(v) for v in row]
        row_clipped = sum(len(s) > max_cell_chars for s in cells)
        line = "\t".join(s if len(s) <= max_cell_chars else s[:max_cell_chars] + "…" for s in cells)
        if used + 1 + len(line) > budget:
            output_truncated = True
            break
        lines.append(line)
        used += 1 + len(line)
        returned += 1
        clipped += row_clipped
    lines.append(f"-- {returned} row(s){' (truncated, raise limit or add WHERE)' if truncated else ''}")
    if clipped:
        lines.append(f"-- {clipped} cell(s) truncated at {max_cell_chars} escaped chars; "
                     "raise max_cell_chars (max 16000) or use length()/substr() with a stable key")
    if output_truncated:
        lines.append(f"-- output truncated at {MAX_QUERY_CHARS} chars; select fewer columns or "
                     "page with ORDER BY a stable key and LIMIT/OFFSET")
    return "\n".join(lines)


_SIG_METHOD = re.compile(r"^(L[^;]+;)->([^(]+)(\(.*)$")
_PROTO_SPACES = re.compile(r"\(([^)]*)\)")


def _parsed_dex(src: str, member: str | None):
    key = (src, member)
    if key not in _dex_cache:
        if len(_dex_cache) >= 2:
            _dex_cache.pop(next(iter(_dex_cache)))
        _dex_cache[key] = W.load_dex(src, member)[1]
    return _dex_cache[key]


@mcp.tool()
def decode(dataset_id: str, method: str, max_chars: int = 12000) -> str:
    """Disassemble one method to smali-like text. method = 'Lcom/x/Y;->name(I)V'.

    If the class exists in several dex files, all definitions are printed (each with its file_id).
    Offsets are in 16-bit code units (hex), the same as smali/dexdump.
    """
    m = _SIG_METHOD.match(method.replace(" ", ""))
    if not m:
        raise ToolError("method must look like 'Lcom/x/Y;->name(I)V'")
    cls, name, proto = m.group(1), m.group(2), m.group(3)
    conn = _ro(_dataset(dataset_id)["db"])
    try:
        rows = conn.execute(
            "SELECT m.file_id, d.source, d.member FROM methods m JOIN dex_files d USING(file_id) "
            "WHERE m.class=? AND m.name=? AND m.proto=?", (cls, name, proto)).fetchall()
    finally:
        conn.close()
    if not rows:
        return f"not found: {method} (check with: SELECT * FROM methods WHERE class='{cls}' AND name='{name}')"
    out: list[str] = []
    for file_id, src, member in rows:
        d = _parsed_dex(src, member or None)
        for e in d.get_encoded_methods():
            if (e.get_class_name() == cls and e.get_name() == name
                    and W.norm_proto(e.get_descriptor()) == proto):
                code = e.get_code()
                head = f"# file_id={file_id} {cls}->{name}{proto} access={e.get_access_flags_string()}"
                if code is None:
                    out.append(head + " (no code: abstract/native)")
                    break
                regs = getattr(code, "get_registers_size", lambda: "?")()
                out.append(f"{head} registers={regs}")
                off = 0
                for ins in code.get_bc().get_instructions():
                    nm = ins.get_name()
                    text_out = ins.get_output()
                    if nm.startswith("invoke"):  # 只规整方法签名；const-string 等含字符串常量的不能动
                        text_out = _PROTO_SPACES.sub(lambda m: "(" + m.group(1).replace(" ", "") + ")", text_out)
                    out.append(f"{off // 2:04x}: {nm:<24} {text_out}")
                    off += ins.get_length()
                break
    text = "\n".join(out)
    return text if len(text) <= max_chars else text[:max_chars] + f"\n… truncated at {max_chars} chars"


@mcp.tool()
def find_refs(dataset_id: str, kind: str, target: str, limit: int = 100) -> str:
    """Find where something is used. Scans instructions of the dex files that can contain a hit.

    kind='method'  target='Lcom/x/Y;->name(I)V'  -> invoke-* call sites (callers)
    kind='field'   target='Lcom/x/Y;->name:I'    -> iget/iput/sget/sput sites
    kind='string'  target='exact string text'    -> const-string users
    kind='type'    target='Lcom/x/Y;'            -> const-class/new-instance/check-cast/... sites
    Output columns: file_id, class, method, proto, offset(hex code units), op.
    Subclass overrides / interface dispatch are NOT resolved: an invoke names the static receiver type.
    """
    if kind not in ("method", "field", "string", "type"):
        raise ToolError("kind must be method | field | string | type")
    limit = max(1, min(int(limit), 1000))
    target = target.replace(" ", "") if kind in ("method", "field") else target
    ds = _dataset(dataset_id)
    conn = _ro(ds["db"])
    try:
        if kind == "method":
            m = _SIG_METHOD.match(target)
            if not m:
                raise ToolError("method target must look like 'Lcom/x/Y;->name(I)V'")
            cand = conn.execute("SELECT DISTINCT file_id FROM method_ids WHERE class=? AND name=? AND proto=?",
                                (m.group(1), m.group(2), m.group(3))).fetchall()
        elif kind == "field":
            m = re.match(r"^(L[^;]+;)->([^:]+):(.+)$", target)
            if not m:
                raise ToolError("field target must look like 'Lcom/x/Y;->name:I'")
            cand = conn.execute("SELECT DISTINCT file_id FROM field_ids WHERE class=? AND name=? AND type=?",
                                (m.group(1), m.group(2), m.group(3))).fetchall()
        elif kind == "string":
            cand = conn.execute("SELECT DISTINCT file_id FROM strings WHERE value=?", (target,)).fetchall()
        else:
            cand = conn.execute("SELECT file_id FROM dex_files").fetchall()
        dex_rows = conn.execute("SELECT file_id, source, member FROM dex_files").fetchall()
        files = {r[0]: (r[1], r[2] or None) for r in dex_rows}
        names = {r[0]: (r[2] or os.path.basename(r[1])) for r in dex_rows}
    finally:
        conn.close()
    cand_ids = sorted(r[0] for r in cand)
    if not cand_ids:
        return f"-- 0 hit(s): no dex file references this {kind}"
    jobs = [(files[i][0], files[i][1], i, kind, target) for i in cand_ids]
    started = time.time()
    hits: list[tuple] = []
    with ProcessPoolExecutor(max_workers=min(_workers(), len(jobs)), initializer=W.init_worker) as pool:
        for file_id, rows in pool.map(W.scan_refs, jobs):
            hits.extend((file_id, *r) for r in rows)
    hits.sort(key=lambda h: (h[0], h[1], h[2], h[3], h[4]))
    shown = hits[:limit]
    lines = ["file_id\tclass\tmethod\tproto\toffset\top"]
    lines += [f"{h[0]}\t{h[1]}\t{h[2]}\t{h[3]}\t{h[4]:04x}\t{h[5]}" for h in shown]
    lines.append(f"-- {len(shown)} of {len(hits)} hit(s); scanned {len(jobs)} dex "
                 f"({', '.join(names[i] for i in cand_ids[:6])}{'…' if len(cand_ids) > 6 else ''}) "
                 f"in {time.time() - started:.1f}s")
    return "\n".join(lines)


@mcp.tool()
def apk_info(path: str) -> str:
    """Package name, version, SDK levels, permissions and component names of an APK (from its manifest)."""
    from androguard.core.apk import APK

    p = _check_path(path)
    apk = APK(str(p))
    return json.dumps({
        "package": apk.get_package(),
        "versionName": apk.get_androidversion_name(),
        "versionCode": apk.get_androidversion_code(),
        "minSdk": apk.get_min_sdk_version(),
        "targetSdk": apk.get_target_sdk_version(),
        "application": apk.get_attribute_value("application", "name"),
        "mainActivity": apk.get_main_activity(),
        "permissions": sorted(apk.get_permissions()),
        "activities": apk.get_activities(),
        "services": apk.get_services(),
        "receivers": apk.get_receivers(),
        "providers": apk.get_providers(),
    }, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run(transport="stdio")
