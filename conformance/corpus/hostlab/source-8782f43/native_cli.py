"""Owned, bounded DexSQL CLI session with lossless hex cells for bulk audit data."""
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import time
import uuid
from concurrent.futures import Future, TimeoutError as FutureTimeout
from collections import deque

import analysis_batch as batch
import install_dexsql
import process_control


class CliSession:
    def __init__(self, apk, timeout=900, threads=2):
        self.apk = Path(apk).resolve(strict=True)
        self.timeout, self.threads = timeout, threads
        self.deadline = time.monotonic()+timeout
        self.queries = 0
        self.messages = queue.Queue(maxsize=8)
        self.closed = threading.Event()
        self.lines = deque()
        self.pending = b""
        self.eof = False

    def __enter__(self):
        started = time.monotonic()
        binary = install_dexsql.verify()
        batch.archive_inventory(self.apk)
        self.errors = tempfile.TemporaryFile()
        try:
            self.process = subprocess.Popen([str(binary), "--threads", str(self.threads),
                "query", "--input", str(self.apk), "--interactive"], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=self.errors, env=batch.child_environment(self.apk, self.threads),
                start_new_session=os.name != "nt")
            self.reader = threading.Thread(target=self.read, daemon=True, name="hostlab-dexsql-cli-reader")
            self.reader.start()
            self.files = {int(r["file_id"]):r["entry_name"] for r in self.rows("SELECT file_id,entry_name FROM dex_files ORDER BY file_id")}
            batch.verify_inventory(batch.archive_inventory(self.apk), self.files)
            self.opened = {"backend":"dexsql", "transport":"cli_hex_v1", "prepare_ms":(time.monotonic()-started)*1000,
                           "files":self.files, "cache":"memory_session", "source_diagnostics":[]}
            return self
        except BaseException:
            self.__exit__(RuntimeError, None, None)
            raise

    def read(self):
        while not self.closed.is_set():
            try:
                # read1 returns available pipe bytes without waiting for a full
                # block. Small shape/marker replies must remain responsive.
                item = self.process.stdout.read1(64*1024)
            except (OSError, ValueError):
                item = RuntimeError("native audit CLI output read failed")
            while not self.closed.is_set():
                try:
                    self.messages.put(item, timeout=.1)
                    break
                except queue.Full:
                    continue
            if not item or isinstance(item, Exception): break

    def line(self):
        while not self.lines:
            if self.eof:
                return b""
            remaining = self.deadline-time.monotonic()
            if remaining <= 0:
                raise TimeoutError("native audit deadline exhausted")
            try:
                chunk = self.messages.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError("native audit CLI response timed out") from None
            if isinstance(chunk, Exception):
                raise chunk
            if not chunk:
                self.eof = True
                line, self.pending = self.pending, b""
                return line
            fragments = (self.pending+chunk).split(b"\n")
            self.pending = fragments.pop()
            if len(self.pending) > 4*1024*1024 or any(len(part)+1 > 4*1024*1024 for part in fragments):
                raise RuntimeError("native CLI row exceeds its byte budget")
            self.lines.extend(part+b"\n" for part in fragments)
        if time.monotonic() >= self.deadline:
            raise TimeoutError("native audit deadline exhausted")
        return self.lines.popleft()

    def write(self, sql):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("native audit deadline exhausted")
        if len(sql.encode()) > 256*1024:
            raise RuntimeError("native audit SQL exceeds its byte budget")
        done = Future()
        def send():
            try:
                self.process.stdin.write(sql.encode("utf-8"))
                self.process.stdin.flush()
                done.set_result(None)
            except BaseException as exc:
                done.set_exception(exc)
        writer = threading.Thread(target=send, daemon=True, name="hostlab-dexsql-cli-writer")
        writer.start()
        try:
            done.result(timeout=max(.001, self.deadline-time.monotonic()))
        except FutureTimeout:
            process_control.terminate_tree(self.process)
            writer.join(timeout=3)
            raise TimeoutError("native audit CLI input timed out") from None

    def table(self, sql, *, expected=None):
        marker = "__hostlab_end_"+uuid.uuid4().hex
        self.write(sql.rstrip(";\n")+";\nSELECT '"+marker+"' AS hostlab_boundary;\n")
        columns, used = None, 0
        while True:
            line = self.line()
            if not line: raise RuntimeError("native audit CLI exited before a complete result")
            used += len(line)
            if used > 512*1024*1024: raise RuntimeError("native audit CLI response exceeds byte budget")
            text = line.decode("utf-8", "strict").strip()
            if not text.startswith("|") or not text.endswith("|"): continue
            cells = [cell.strip() for cell in text[1:-1].split("|")]
            if cells == [marker]:
                if columns is None: raise RuntimeError("native audit CLI did not return the requested columns")
                return
            if cells == ["hostlab_boundary"]: continue
            if columns is None:
                if expected is not None and cells != expected:
                    raise RuntimeError("native audit CLI column identity mismatch")
                columns = cells
                yield columns, None
                continue
            if len(cells) != len(columns): raise RuntimeError("ambiguous native CLI row")
            yield columns, cells

    def rows(self, sql, *, page_size=1000, max_rows=500000, max_bytes=128*1024*1024):
        if "ORDER BY" not in sql.upper(): raise ValueError("native audit requires stable ordering")
        columns = None
        for names, row in self.table("SELECT * FROM ("+sql+") AS hostlab_shape LIMIT 0"):
            if row is not None: raise RuntimeError("native audit shape query unexpectedly returned data")
            columns = names
        if not columns or len(columns) != len(set(columns)): raise RuntimeError("ambiguous native audit columns")
        def identifier(name): return '"'+name.replace('"','""')+'"'
        projected = ["CASE WHEN "+identifier(name)+" IS NULL THEN 'N' ELSE hex(CAST("+identifier(name)+" AS TEXT)) END AS "+identifier(name) for name in columns]
        statement = "SELECT "+",".join(projected)+" FROM ("+sql+") AS hostlab_rows"
        used, count = 0, 0
        for names, cells in self.table(statement, expected=columns):
            if cells is None: continue
            count += 1
            if count > max_rows: raise RuntimeError("native audit exceeded its complete row budget")
            decoded = []
            for cell in cells:
                if cell == "N": value = None
                else:
                    try: value = bytes.fromhex(cell).decode("utf-8", "strict")
                    except (ValueError, UnicodeError): raise RuntimeError("native audit returned a malformed hex cell") from None
                used += len(value.encode()) if value is not None else 0
                if used > max_bytes: raise RuntimeError("native audit exceeded its complete byte budget")
                decoded.append(value)
            yield dict(zip(names, decoded))
        self.queries += 1

    def all(self, sql, **bounds): return list(self.rows(sql, **bounds))

    def __exit__(self, error, *_):
        self.closed.set()
        try:
            if not hasattr(self, "process"):
                return
            if error is None and self.process.poll() is None:
                self.process.stdin.write(b".exit\n"); self.process.stdin.flush()
                self.process.stdin.close()
                try: self.process.wait(timeout=3)
                except subprocess.TimeoutExpired: process_control.terminate_tree(self.process)
                if self.process.returncode: raise RuntimeError("native audit CLI exited unsuccessfully")
            elif self.process.poll() is None:
                process_control.terminate_tree(self.process)
            if error is None and self.process.returncode not in (None, 0):
                raise RuntimeError("native audit CLI exited unsuccessfully")
        finally:
            if hasattr(self, "process"):
                if self.process.poll() is None:
                    process_control.terminate_tree(self.process)
                try:
                    self.process.stdin.close()
                except BrokenPipeError:
                    pass
                self.process.stdout.close()
            if hasattr(self, "reader"):
                self.reader.join(timeout=3)
            self.errors.close()
