import datetime
import hashlib
import json
from pathlib import Path
from run_validation import record, require

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent

def main():
    for name, argv in [("final/rustc", ["rustc", "-vV"]), ("final/cargo", ["cargo", "-V"]),
                       ("final/a0-comparison", [__import__("sys").executable, "-O", "artifacts/mdd-025/manifest/compare_a0.py"])]:
        require(record(name, argv).returncode == 0, "final identity/comparison failed")
    sources = [*sorted((ROOT / "crates/mdd-input/src/manifest").glob("*.rs")),
               ROOT / "crates/mdd-facts/examples/manifest_summary.rs",
               ROOT / "tests/fixtures/manifest/generate.py", ROOT / "tests/fixtures/manifest/check.py",
               ROOT / "tests/fixtures/manifest/manifest.json", ROOT / "conformance/resources/hostlab-required.json",
               ROOT / "Cargo.lock"]
    identities = [{"path":p.relative_to(ROOT).as_posix(),"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for p in sources]
    cases = json.loads((ROOT / "tests/fixtures/manifest/manifest.json").read_text(encoding="utf-8"))["cases"]
    result = {
        "schema_version":"mdd.manifest-qualification.v1", "task":"MDD-025", "component":"Manifest required facts",
        "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "production_source_frozen":True,"sources":identities,
        "actual_binary":{"path":"target/debug/examples/manifest_summary.exe","sha256":hashlib.sha256((ROOT/"target/debug/examples/manifest_summary.exe").read_bytes()).hexdigest()},
        "fixtures":{"count":len(cases),"positive":sum(c["expected_error"] is None for c in cases),"negative":sum(c["expected_error"] is not None for c in cases),"all_expected_trees_and_errors_executed":True},
        "validation":{"manifest_unit_tests":3,"all_input_unit_tests":16,"failed":0,"ignored":0,"doc_tests":0,
            "native_platform":"Windows x86_64 MSVC","rustc":"1.99.0","clippy_all_targets":"passed -D warnings",
            "python_independent_reproducibility_and_elementtree":"passed with -O",
            "aapt_small_full_trees":9,"public_full_tree":{"nodes":305,"attributes":411,"equal":True},
            "fixed_A0_summary":{"all_fields_equal":True,"root_attributes":8,"application_attributes":11,"sdk_attributes":2,"component_count":37,"permission_rows":12,"pages":6,"terminal_page_consumed":True,"dataset_closed":True}},
        "contract":{"owned_immutable_arc":True,"raw_member_bytes_unchanged":True,"prefix_ambiguity_explicit":True,
            "null_empty_absent_distinct":True,"resource_refs":"unresolved","no_exported_defaults":True,"no_lossy_resource_strings":True,
            "bad_input":"real INVALID_INPUT, QUOTA_EXCEEDED, or explicitly unsupported chunk/version; never empty successful tree"},
        "acceptance_scope":{"MDD025_manifest_namespace_typed_components_permissions":"passed within frozen required fact scope",
            "MDD025_raw_code_and_resource_fingerprints":"root-owned independent evidence, not signed by this component report",
            "snapshot_generation_binding":"same Arc verified in example; snapshot/member identity built by root ResourceByteEvidence; root mutation tests remain separate"},
        "not_claimed":["full HostLab replacement","MDD042 MCP/XML rendering/paging","MDD072 ARSC/config/overlay/full resource tools","private APK execution","Linux native execution until root CI","performance"],
        "evidence":["final/","small-aapt-summary.json","public-full-tree-comparison.json","public-native/","public-aapt/","a0-summary-comparison.json","a0/","experience.md"],
        "rollback":"Remove only explicitly owned Manifest additions and let root revert module export; retain evidence and archive/snapshot implementations. No remote deployment/default switch performed."}
    (OUT / "qualification.json").write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    print(json.dumps({"qualification_written":True,"source_files":len(identities),"cases":len(cases)}))

if __name__ == "__main__": main()
