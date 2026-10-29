#!/usr/bin/env python3
"""Observe only SQLite concatenation semantics used by the bounded fixture."""
import json
import sqlite3


def main():
    db = sqlite3.connect(":memory:")
    text = db.execute("SELECT ? || ?", ("A\0", "😀")).fetchone()[0]
    null = db.execute("SELECT NULL || ?", ("x",)).fetchone()[0]
    blob_hex, blob_type = db.execute("SELECT hex(X'00FF'||X'41'),typeof(X'00FF'||X'41')").fetchone()
    units = list(int.from_bytes(text.encode("utf-16-le")[i:i + 2], "little")
                 for i in range(0, len(text.encode("utf-16-le")), 2))
    print(json.dumps({"sqlite_version": sqlite3.sqlite_version, "text_utf16": units,
                      "null": null, "blob_concat_hex": blob_hex, "blob_concat_type": blob_type,
                      "isolated_surrogate_sqlite_text": "not_run; Python SQLite UTF-8 binding cannot encode it",
                      "scope": "SQLite micro-oracle only; no A0/A1 or full dialect qualification"}))


if __name__ == "__main__":
    main()
