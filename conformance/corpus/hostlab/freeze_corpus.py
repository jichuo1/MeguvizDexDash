"""Freeze M0 HostLab contracts from exact source and recorded observations.

This does not produce query goldens or qualify an engine. No APK is opened.
"""
from __future__ import annotations
import ast
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCE = Path(__file__).resolve().parent / "source-8782f43"
COMMIT = "8782f43d537c442905123e35af325c412caa5188"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def write(path, value):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def source_info(name):
    p = SOURCE / name
    return {"path": p.relative_to(ROOT).as_posix(), "sha256": digest(p),
            "source_commit": COMMIT, "origin_url": "https://raw.githubusercontent.com/jichuo1/innocent-lab-host-analysis/" + COMMIT + "/tools/hostlab/" + name}


def decorated_tools(name):
    p = SOURCE / name
    text = p.read_text(encoding="utf-8")
    result = []
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(".tool" in ast.get_source_segment(text, d) for d in node.decorator_list):
            result.append({"name": node.name, "arguments_source": ast.get_source_segment(text, node.args),
                           "signature": ast.unparse(node.args), "docstring": ast.get_docstring(node),
                           "line": node.lineno, "end_line": node.end_lineno, "source": source_info(name)})
    return result


def sql_fragments(name):
    text = (SOURCE / name).read_text(encoding="utf-8")
    fragments = []
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, (ast.Assign, ast.Return, ast.Call)):
            if isinstance(node, ast.Assign): candidate = node.value
            elif isinstance(node, ast.Return): candidate = node.value
            else:
                if not node.args or not isinstance(node.func, ast.Attribute) or node.func.attr not in {"rows", "all", "table", "execute"}: continue
                candidate = node.args[0]
            if candidate is None: continue
            if any(isinstance(c, ast.Constant) and isinstance(c.value, str) and re.search(r"\bSELECT\b|\bWITH\b", c.value) for c in ast.walk(candidate)):
                expression = ast.get_source_segment(text, candidate)
                fragments.append({"line": candidate.lineno, "end_line": candidate.end_lineno,
                                  "expression": expression, "expression_kind": type(candidate).__name__,
                                  "source": source_info(name), "execution_status": "not_run"})
    seen = set()
    return [f for f in fragments if not ((k := (f["line"], f["end_line"], f["expression"])) in seen or seen.add(k))]


def main():
    source_manifest = json.loads((SOURCE / "manifest.json").read_text())
    verified = []
    for item in source_manifest["files"]:
        if item["status"] != "obtained": continue
        p = ROOT / item["path"]
        if digest(p) != item["sha256"] or p.stat().st_size != item["bytes"]: raise ValueError("Frozen source changed: " + str(p))
        verified.append(item)
    historical_index = read("evidence/index.json")
    for item in historical_index["files"]:
        if digest(ROOT / item["path"]) != item["sha256"]: raise ValueError("Historical evidence changed: " + item["path"])
    schema_path = ROOT / "artifacts/mdd-003/dexsql-0.1.0-windows-tables.txt"
    relations = []
    for line in schema_path.read_text().splitlines():
        if not line.strip(): continue
        if not line.startswith(" "):
            relations.append({"name": line.strip(), "columns": []})
        else:
            name, kind = line.split(maxsplit=1)
            relations[-1]["columns"].append({"name": name, "data_type": kind.rstrip("?"), "nullable": kind.endswith("?")})
    if len(relations) != 56: raise ValueError("Unexpected relation count")
    required = "dex_files strings types classes class_interfaces class_fields class_methods methods annotation_directory_entries annotation_set_entries annotations annotation_elements method_strings code_items method_calls method_field_accesses method_used_types".split()
    for relation in relations:
        relation["required_by_hostlab"] = relation["name"] in required
        relation["qualification"] = "reference_schema_only"
    write("conformance/manifests/relations.json", {"schema_version": "mdd.reference-relations.v1", "reference_release": "0.1.0", "reference_platform": "windows_amd64", "schema_capture": "artifacts/mdd-003/schema-capture.json", "schema_sha256": digest(schema_path), "required_count": len(required), "relations": relations, "limits": ["Not an implemented mdd relation", "0.1.1 schema has not been recaptured in this environment"]})
    native = {}
    for version in ("0.1.0", "0.1.1"):
        rows = read("evidence/compatibility/" + version + "/mcp-records.json")
        native[version] = next(r["message"]["result"]["tools"] for r in rows if r.get("direction") == "response" and "tools" in r.get("message", {}).get("result", {}))
        if len(native[version]) != 12: raise ValueError("Unexpected native tool count")
    legacy = decorated_tools("dexq/server.py")
    remote = decorated_tools("remote_mcp.py")
    if len(legacy) != 8 or len(remote) != 12: raise ValueError("Unexpected wrapper tool count")
    write("conformance/manifests/tools-and-options.json", {"schema_version": "mdd.reference-tools.v1", "native_mcp": native, "hostlab_direct_native_tools": ["open_dataset", "query", "decode", "get_manifest", "close_dataset"], "legacy_dexq": legacy, "remote_orchestration": remote, "paging_units": {"query": "rows; offset re-executes SQL", "decode_smali": "display UTF-8 bytes", "decode_method_list": "method_offset", "manifest_xml": "display UTF-8 bytes", "manifest_summary": "permission rows", "read_resource_hex": "raw bytes", "read_resource_auto_text_xml": "display UTF-8 bytes"}, "implementation": "not_implemented", "source_commit": COMMIT})
    definitions = [
        ("Q01", "Input inventory and string pools", ["native_cli.py", "native_graph.py"], ["dex_files"], "SELECT file_id,entry_name FROM dex_files ORDER BY file_id", ["ordered occurrence list", "snapshot-local file_id and string_pool_id"]),
        ("Q02", "Class metadata and wildcard members", ["native_graph.py"], ["classes", "class_fields", "class_methods"], "SELECT cf.* FROM class_fields cf WHERE class_descriptor IN ('Lfixture/A;') ORDER BY file_id,class_idx,kind,field_idx", ["descriptor IN list (80 member / 120 meta batches)", "all wildcard columns from full reference schema"]),
        ("Q03", "Interfaces join with local identities", ["native_graph.py"], ["class_interfaces", "classes"], "SELECT ci.interface_descriptor,c.descriptor FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE c.descriptor IN ('Lfixture/A;') ORDER BY ci.file_id,ci.class_idx,ci.ordinal", ["descriptor IN list", "two-key join"]),
        ("Q04", "Ordered Signature annotation hierarchy", ["native_graph.py"], ["annotation_directory_entries", "annotation_set_entries", "annotations", "annotation_elements", "strings", "types"], "SELECT file_id,annotation_off,ordinal,value_index FROM annotation_elements WHERE ((file_id=0 AND annotation_off IN (256))) AND depth=1 AND value_kind='string' ORDER BY file_id,annotation_off,ordinal", ["per-file local-index sets", "pool mapping", "nullable annotation_set_off", "preserve string element ordinal"]),
        ("Q05", "Definition-to-reference return discovery", ["native_graph.py"], ["class_methods", "methods"], "SELECT DISTINCT m.class_descriptor FROM class_methods c JOIN methods m ON m.file_id=c.file_id AND m.method_idx=c.method_idx WHERE m.return_descriptor='Lfixture/Result;' ORDER BY m.class_descriptor", ["return descriptor scalar", "DISTINCT explicit"]),
        ("Q06", "String candidate and LIKE/ESCAPE", ["native_rules.py"], ["method_strings"], "SELECT DISTINCT file_id,method_idx,value FROM method_strings WHERE method_class IN ('Lfixture/A;') AND (value LIKE '%quality settings:%' OR value LIKE '%pref\\_player\\_mediaSource\\_quality\\_wifi\\_key%' ESCAPE '\\') ORDER BY file_id,method_idx,value", ["owner descriptor set", "literal escaped underscore", "Python exact second filter retained"]),
        ("Q07", "Complete class count", ["native_audit.py"], ["classes"], "SELECT COUNT(*) AS n FROM classes ORDER BY n", ["none"]),
        ("Q08", "Per-DEX classes and member surface", ["native_surface.py"], ["classes", "class_fields", "class_methods"], "SELECT file_id,class_def_idx,descriptor,superclass_descriptor FROM classes WHERE file_id=0 AND (descriptor LIKE 'Lfixture/%' ESCAPE '\\') ORDER BY file_id,class_def_idx", ["file_id", "family prefix OR + lower/LIKE", "exact Python classifier"]),
        ("Q09", "Raw body range and exact membership", ["native_surface.py"], ["code_items"], "SELECT method_idx,insns_off,insns_size FROM code_items WHERE file_id=0 AND method_idx BETWEEN 0 AND 8 ORDER BY method_idx", ["file_id", "min/max method IDs plus exact membership", "insns_size code units x2 bytes"]),
        ("Q10", "Call-site multiplicity aggregate", ["native_surface.py"], ["method_calls"], "SELECT file_id,method,callee,COUNT(*) AS n FROM method_calls WHERE file_id=0 AND (callee_class LIKE 'Lfixture/%' ESCAPE '\\') GROUP BY file_id,method,callee ORDER BY file_id,method,callee", ["family/protocol predicates", "duplicates count rather than deduplicated edges"]),
        ("Q11", "Protocol definitions", ["native_surface.py"], ["class_methods"], "SELECT file_id,method_descriptor FROM class_methods WHERE file_id=0 AND (class_descriptor IN ('Lfixture/Protocol;') OR class_descriptor LIKE 'Lcom/bapis/%Moss;') ORDER BY file_id,class_idx,method_idx", ["protocol descriptor set", "case-sensitive Python semantics remain adapter"]),
        ("Q12", "Locate and four refs generators", ["analysis_plan.py"], ["classes", "class_methods", "class_fields", "method_strings", "method_calls", "method_field_accesses", "method_used_types"], "SELECT file_id,method AS descriptor FROM method_calls WHERE callee='Lfixture/A;->f()V' ORDER BY file_id,method_idx", ["kind enum", "name/owner/target strings SQL quoted", "LIMIT limit+1 overflow detection"]),
        ("Q13", "CLI shape and lossless value wrapper", ["native_cli.py"], required, "SELECT * FROM (SELECT file_id,entry_name FROM dex_files ORDER BY file_id) AS hostlab_shape LIMIT 0", ["arbitrary ordered source SQL", "escaped identifiers", "CASE NULL sentinel + hex(CAST AS TEXT)", "request-specific marker"]),
        ("Q14", "Stable paging SELECT/WITH", ["analysis_plan.py", "analysis_paging.py", "analysis_batch.py"], required, None, ["caller raw SELECT/WITH <=12000 chars", "outer stable ORDER BY", "independent response limit/offset", "long values and duplicate/zero rows"]),
        ("Q15", "Legacy SQLite definitions and TSV", ["dexq/server.py", "analysis_plan.py"], ["dex_files", "classes", "methods", "fields", "method_ids", "field_ids", "strings", "meta"], "SELECT file_id,class||'->'||name||proto AS descriptor FROM methods WHERE name='f' ORDER BY file_id,descriptor", ["explicit sqlite dialect", "TSV previews distinct from complete SQL values", "length/substr and concatenation"]),
        ("Q16", "Native TEMP and multistatement", [], [], None, ["named_temp_queries", "dependency mutation", "multiple statements", "broader product profile only; no HostLab v1 expansion"]),
    ]
    corpus = []
    fragment_count = 0
    for ident, title, names, tables, sql, params in definitions:
        fragments = [f for name in names for f in sql_fragments(name)]
        fragment_count += len(fragments)
        corpus.append({"id": ident, "title": title, "source_commit": COMMIT, "dialect": "sqlite" if ident == "Q15" else "dexsql", "required_profile": "hostlab-audit-v1" if ident not in {"Q15", "Q16"} else "legacy-sqlite-or-public-product", "source_expressions": fragments, "representative_sql": sql, "representative_parameter_source": "synthetic fixture values substituted into frozen source shapes; not a recorded production request", "dynamic_parameter_classes": params, "relations": tables, "relation_schemas": {r["name"]: r["columns"] for r in relations if r["name"] in tables} if ident != "Q15" else {"source": "dexq/server.py:108-118; separate SQLite definitions"}, "row_semantics": {"null": "preserve NULL separately from empty text and bytes", "duplicates": "preserve multiplicity unless SQL explicitly DISTINCT/GROUP BY", "ordering": "source ORDER BY; unordered results compared as multisets", "integer_encoding": "reference native MCP exact decimal int64/uint64 strings"}, "result_schema_observed": None, "golden": None, "execution_status": "not_run", "blocking_reason": "Current environment has no validated full HostLab APKs or fresh completed corpus result goldens."})
    from static_contracts import enrich
    corpus = enrich(corpus, relations, SOURCE, ROOT)
    fragment_count = sum(len(q["source_expressions"]) for q in corpus)
    out = ROOT / "conformance/corpus/hostlab/queries.jsonl"
    out.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in corpus), encoding="utf-8")
    profiles = ["hostlab-audit-v1", "dexsql-0.1.0-compat-v1", "dexsql-0.1.1-compat-v1"]
    write("conformance/manifests/profile-requirements.json", {"schema_version": "mdd.profile-requirements.v1", "profiles": [{"id": p, "admitted": False, "status": "blocked", "required_query_families": [x["id"] for x in corpus if x["required_profile"] == "hostlab-audit-v1"] if p == "hostlab-audit-v1" else [x["id"] for x in corpus], "required_native_tools": ["open_dataset", "query", "decode", "get_manifest", "close_dataset"] if p == "hostlab-audit-v1" else sorted(x["name"] for x in native["0.1.0"]), "required_input_coverage": "complete", "required_fact_coverage": "complete within declared required scope", "required_execution": {"complete": True, "truncated": False, "has_more": False, "next_cursor": None}, "full_process_fallback_allowed_for_qualification": False} for p in profiles], "distinguish": ["implementation", "sql_dialect", "compatibility_profile"], "blocking_gates": ["Fresh fully consumed query goldens and errors", "Full HostLab FEATURE/fingerprint/report equivalence", "SQLite virtual-table semantic qualification", "Linux and Windows native validation"]})
    inventory = read("evidence/hostlab_integration_inventory.json")
    pipeline = read("evidence/hostlab_public_pipeline.json")
    samples = read("evidence/hostlab_verification.json")["samples"]
    bins = []
    binary = Path(r"D:\Bilibili_Innocent_Lab\tools\hostlab\vendor\dexsql\0.1.0\dexsql-windows-amd64.exe")
    expected = inventory["production_dexsql"]["windows_amd64"]["sha256"]
    actual = digest(binary)
    if actual != expected: raise ValueError("Available Windows reference binary mismatch")
    bins.append({"group": "A0", "version": "0.1.0", "platform": "windows_amd64", "actual_path": str(binary), "expected_sha256": expected, "actual_sha256": actual, "bytes": binary.stat().st_size, "status": "verified_available", "version_observed": "dexsql 0.1.0", "executed_scope": "version/help/schema only", "origin_url": "https://github.com/LSPosed/dexsql-release/releases/download/v0.1.0/dexsql-windows-amd64.exe"})
    for v in ["0.1.0", "0.1.1"]:
        record = pipeline["binaries"][v]
        bins.append({"group": "A0" if v == "0.1.0" else "A1", "version": v, "platform": "linux_amd64", "expected_sha256": record["sha256"], "actual_sha256": None, "status": "not_acquired", "origin_url": "https://github.com/LSPosed/dexsql-release/releases/download/v" + v + "/dexsql-linux-amd64"})
    write("conformance/manifests/engine-binaries.json", {"schema_version": "mdd.reference-binaries.v1", "binaries": bins, "A2": {"status": "not_qualified", "reason": "requires same-workload full-result comparison; compact and existing consumer optimization remain separate"}, "B0": {"status": "not_implemented"}, "B1": {"status": "not_implemented"}})
    corpus_inputs = [{"visibility": "public", "id": "newpipe-0.28.6", "expected_sha256": pipeline["apk"]["sha256"], "expected_bytes": pipeline["apk"]["bytes"], "origin_url": "https://github.com/TeamNewPipe/NewPipe/releases/download/v0.28.6/NewPipe_v0.28.6.apk", "status": "not_acquired", "actual_sha256": None}]
    for s in samples:
        local = Path(r"D:\Bilibili_Innocent_Lab\runtime\hostlab\samples") / s["sha256"]
        files = [{"name": f.name, "bytes": f.stat().st_size} for f in local.iterdir() if f.is_file()] if local.exists() else []
        corpus_inputs.append({"visibility": "restricted", "id": "hostlab-" + str(s["version_code"]), "version_code": s["version_code"], "expected_sha256": s["sha256"], "expected_bytes": s["size"], "status": "not_acquired", "actual_sha256": None, "observed_directory": str(local), "observed_files": files, "acquisition": "explicit authorized HostLab private sample intake; no token or private APK copied", "historical_reference_path": s["path"]})
    write("conformance/manifests/input-corpus.json", {"schema_version": "mdd.input-corpus.v1", "inputs": corpus_inputs, "scope": "Input identity registry only; historical hashes do not prove present bytes", "blocked_gates": ["MDD-005 same-environment A0/A1/A2 baseline", "MDD-003 fully consumed required query goldens", "MDD-054 full HostLab shadow equivalence", "MDD-082 performance qualification"]})
    repo = Path(r"D:\Bilibili_Innocent_Lab\runtime\audit-memory-stability-20261023")
    git_base = ["git", "-c", "safe.directory=" + repo.as_posix(), "-C", str(repo)]
    head = subprocess.run(git_base + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    dirty = subprocess.run(git_base + ["status", "--short"], capture_output=True, text=True, check=True).stdout.splitlines()
    comparisons = []
    for item in verified:
        name = Path(item["path"]).relative_to(SOURCE.relative_to(ROOT))
        p = repo / "tools/hostlab" / name
        comparisons.append({"path": str(name).replace("\\", "/"), "fixed_sha256": item["sha256"], "actual_checkout_sha256": digest(p) if p.exists() else None, "equal": p.exists() and digest(p) == item["sha256"]})
    write("conformance/manifests/source-baseline.json", {"schema_version": "mdd.source-baseline.v1", "project": "MeguvizDexDash", "workspace": str(ROOT), "reference_hostlab_commit": COMMIT, "reference_sources": verified, "actual_hostlab_checkout": {"path": str(repo), "head": head, "dirty": dirty, "fixed_commit_object_locally_available": False, "comparison_to_fixed_sources": comparisons}, "scope_boundary": {"DexMeguviz_required": False, "DexSQL_required_to_build_core": False, "DexKit_replacement": False, "HostLab_business_in_core": False}, "historical_evidence_index_sha256": digest(ROOT / "evidence/index.json"), "historical_files_verified": len(historical_index["files"])})
    write("artifacts/mdd-001/provenance-verification.json", {"task": "MDD-001", "status": "passed_identity_registry", "command": "python conformance/corpus/hostlab/freeze_corpus.py", "source_files_verified": len(verified), "historical_evidence_files_verified": len(historical_index["files"]), "binary_sha256": actual, "input_bytes_verified": 0, "not_qualified": ["Any full HostLab engine result", "Performance", "Runtime Hook/UI"], "missing_inputs": [x["id"] for x in corpus_inputs], "notes": ["Fixed source retrieved as exact-commit public raw files, not represented as a local checkout", "Existing external worktrees left unchanged", "Default local process helper failed; read-only checks rerun through approved process escalation", "Schema discovery failures retained in handoff notes; tables requires a compatibility --input path but does not read it"]})
    write("artifacts/mdd-003/corpus-freeze.json", {"task": "MDD-003", "status": "static_contract_freeze_complete", "query_families": len(corpus), "source_expression_references": fragment_count, "reference_relations": len(relations), "required_relations": len(required), "native_tools_each_version": 12, "legacy_tools": len(legacy), "remote_tools": len(remote), "wildcard_full_schema_saved": ["class_fields", "class_methods"], "queries_jsonl_sha256": digest(out), "fresh_result_goldens": 0, "profile_admitted": False})
    print(json.dumps({"task_001": "identity_registry_verified", "task_003": "static_contracts_frozen_runtime_unqualified", "query_families": len(corpus), "relations": len(relations), "required_relations": len(required), "sources_verified": len(verified), "historical_files_verified": len(historical_index["files"])}, ensure_ascii=False))


if __name__ == "__main__":
    main()
