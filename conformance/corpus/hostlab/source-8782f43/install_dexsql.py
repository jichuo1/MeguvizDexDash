"""Install the pinned native DexSQL backend; no global PATH or MCP changes."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import urllib.request

VERSION = "0.1.0"
ASSETS = {
    ("Windows", "AMD64"): ("dexsql-windows-amd64.exe", "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448"),
    ("Linux", "x86_64"): ("dexsql-linux-amd64", "f9e795e1e33547fdda451f592fe54c85e99c2138575f599540f5a860c1cef00c"),
    ("Darwin", "arm64"): ("dexsql-darwin-arm64", "155724634d727a79015488ee15c51ec32b09e6debc96ebf7d83e0b590e485e1e"),
}
HERE = Path(__file__).resolve().parent
LICENSE_HASHES = {
    # Canonical LF text; the release's CRLF LICENSE has raw SHA 197c30c3...ecde166.
    "LICENSE": "a5e8ba355d3bbc08a1de333b93cfaadff62c1b335454930c3bc8163d710b5a30",
    "LICENSE-AUXILIARY": "91c80095437ed20c2dca7758f63f03e15eedb46aa4854577b5df20c788ecc514",
}


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def asset():
    key = (platform.system(), platform.machine())
    if key not in ASSETS:
        raise RuntimeError("unsupported DexSQL platform: " + "/".join(key))
    return ASSETS[key]


def executable():
    name, _ = asset()
    override = os.environ.get("HOSTLAB_DEXSQL")
    return Path(override).expanduser().resolve() if override else HERE / "vendor/dexsql" / VERSION / name


def verify(path=None):
    path = Path(path) if path else executable()
    _, expected = asset()
    if not path.is_file() or sha256(path) != expected:
        raise RuntimeError("pinned DexSQL is missing or failed SHA-256 verification; run install_dexsql.py")
    return path


def status():
    try:
        path = verify()
        return {"available": True, "version": VERSION, "sha256": asset()[1], "path": str(path)}
    except (OSError, RuntimeError) as exc:
        return {"available": False, "version": VERSION, "reason": str(exc)}


def install():
    if os.environ.get("HOSTLAB_DEXSQL"):
        return verify()  # An explicit override is never downloaded to or overwritten.
    target = executable()
    notices = HERE / "vendor/dexsql"
    for name, expected in LICENSE_HASHES.items():
        canonical = (notices / name).read_bytes().replace(b"\r\n", b"\n")
        if hashlib.sha256(canonical).hexdigest() != expected:
            raise RuntimeError("bundled DexSQL license failed verification: " + name)
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        url = f"https://github.com/LSPosed/dexsql-release/releases/download/v{VERSION}/{asset()[0]}"
        # Unique staging file avoids exposing a partial executable to other callers.
        with tempfile.NamedTemporaryFile(dir=target.parent, suffix=".download", delete=False) as stream:
            temporary = Path(stream.name)
            with urllib.request.urlopen(url, timeout=120) as response:
                copied = 0
                while chunk := response.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > 32 * 1024 * 1024:
                        raise RuntimeError("DexSQL release exceeds download budget")
                    stream.write(chunk)
        verify(temporary)
        temporary.chmod(0o755)
        os.replace(temporary, target)
    verify(target)
    for name in LICENSE_HASHES:
        shutil.copyfile(notices / name, target.parent / name)
    # The native extractor refuses existing output; stage and replace only our own notice file.
    with tempfile.TemporaryDirectory(dir=target.parent, prefix="notices-") as directory:
        exported = Path(directory) / "THIRD_PARTY_NOTICES"
        subprocess.run([str(target), "extract", "licenses", "--output", str(exported)],
                       check=True, timeout=30, stdout=subprocess.DEVNULL)
        os.replace(exported, target.parent / "THIRD_PARTY_NOTICES")
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if not args.check:
        install()
    info = status()
    print(json.dumps(info, indent=2))
    raise SystemExit(0 if info["available"] else 1)
