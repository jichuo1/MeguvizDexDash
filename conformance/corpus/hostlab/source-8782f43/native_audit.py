"""Complete native audit transaction; immutable inputs, one dataset, shared rules."""
import hashlib
from pathlib import Path
import time

import hostlab
import install_dexsql
from audit_common import resource_fingerprints
from native_graph import UnsupportedAudit
from native_session import NativeSession
from native_rules import Rules, CATALOG
import native_surface


def run(apk, *, sha256, surface=False, timeout=900):
    from analysis.run_intake import EXPECTED_FEATURES
    apk = Path(apk).resolve(strict=True)
    if hostlab.digest(apk) != sha256:
        raise RuntimeError("native audit input does not match its immutable APK identity")
    started = time.monotonic()
    phases = {}
    with NativeSession(apk, timeout=timeout, threads=2) as session:
        phases["prepare_ms"] = (time.monotonic()-started)*1000
        began = time.monotonic()
        features, discoveries = Rules(session).run()
        if set(features) != set(EXPECTED_FEATURES):
            raise RuntimeError("native audit did not produce the complete FEATURE set")
        phases["structural_ms"] = (time.monotonic()-began)*1000
        class_count = int(session.all("SELECT COUNT(*) AS n FROM classes ORDER BY n")[0]["n"])
        report = None
        if surface:
            began = time.monotonic()
            report = native_surface.scan(session)
            report["resource_fingerprints"] = resource_fingerprints(apk)
            report["scan_execution"] = {"backend":"dexsql", "workers":2, "dex_files":len(session.files),
                                        "elapsed_ms":(time.monotonic()-began)*1000}
            phases["surface_ms"] = (time.monotonic()-began)*1000
        queries = session.queries
    if hostlab.digest(apk) != sha256:
        raise RuntimeError("native audit APK changed during analysis")
    return {"features":features, "discoveries":discoveries, "surface":report, "class_count":class_count,
        "apk_sha256":sha256, "complete":True, "source_sha_reverified":True,
        "backend":"dexsql", "native":install_dexsql.status(), "reference_sha256":CATALOG["reference_sha256"],
        "phases":phases, "queries":queries, "elapsed_ms":(time.monotonic()-started)*1000}


def write_tsv(path, result, apk_name):
    from analysis.run_intake import EXPECTED_FEATURES
    if (result.get("complete") is not True or result.get("source_sha_reverified") is not True or
            set(result.get("features", {})) != set(EXPECTED_FEATURES) or
            any(f.get("status") not in {"FOUND", "MISSING", "PARTIAL", "AMBIGUOUS"} or not isinstance(f.get("detail"), str)
                for f in result["features"].values())):
        raise RuntimeError("refusing to publish incomplete native FEATURE evidence")
    path = Path(path)
    partial = path.with_suffix(".partial")
    def row(*values):
        return "\t".join(str(v).replace("\t", " ").replace("\r", " ").replace("\n", " ") for v in values)+"\n"
    with partial.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(row("META", "apk", apk_name))
        stream.write(row("META", "class_count", result["class_count"]))
        for name, feature in result["features"].items():
            stream.write(row("FEATURE", name, feature["status"], feature["detail"]))
            for owner, method in result["discoveries"].get(name, []):
                stream.write(row("DISCOVERY", name, owner, method))
        stream.write(row("META", "audit_complete", "true"))
    partial.replace(path)
