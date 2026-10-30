"""Build an isolated tiny conformance executable without changing workspace crates."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "artifacts/mdd-026"

def require(ok, message):
    if not ok: raise RuntimeError(message)

def command(label, argv):
    folder = OUT / label; folder.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(); begin = time.monotonic()
    item = subprocess.run([str(x) for x in argv], cwd=ROOT, capture_output=True, timeout=90)
    (folder / "stdout.txt").write_bytes(item.stdout); (folder / "stderr.txt").write_bytes(item.stderr)
    (folder / "record.json").write_text(json.dumps({"argv":[str(x) for x in argv],"started_utc":started,
        "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"elapsed_seconds":time.monotonic()-begin,
        "exit_code":item.returncode,"measurement_scope":"small conformance development only; not performance",
        "stdout_sha256":hashlib.sha256(item.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(item.stderr).hexdigest()}, indent=2)+"\n", encoding="utf-8")
    return item

def main():
    build = command("probe-build/workspace-lib", ["cargo","build","-p","mdd-facts","--lib","--locked","--offline","--message-format=json"])
    require(build.returncode == 0, "fact library build failed")
    artifacts = {}
    for line in build.stdout.splitlines():
        data = json.loads(line)
        if data.get("reason") == "compiler-artifact":
            libs = [p for p in data.get("filenames", []) if p.endswith(".rlib")]
            if len(libs) == 1: artifacts[data["target"]["name"]] = libs[0]
    executable = OUT / "native_probe.exe"
    argv = ["rustc","--edition=2024","--crate-name","mdd_fact_conformance","conformance/facts/native_probe.rs",
            "-L","dependency=target/debug/deps","-o",executable]
    for name in ["mdd_dex","mdd_facts","mdd_input","mdd_types","serde_json"]:
        require(name in artifacts, "missing exact build artifact: " + name)
        argv += ["--extern", name + "=" + artifacts[name]]
    compiled = command("probe-build/native", argv); require(compiled.returncode == 0, "isolated probe compilation failed")
    cases = {
        "classic": ["tests/fixtures/references/generated/classic-035.dex"],
        "shared-code": ["tests/fixtures/references/generated/shared-code-035.dex"],
        "dynamic": ["tests/fixtures/references/generated/poly-custom-038.dex"],
        "annotations": ["tests/fixtures/annotations/generated/annotations-038.dex"],
        "parameter-positions-unknown": ["tests/fixtures/annotations/generated/bad-parameter-arity.dex"],
        "annotations-bad-independent-scope": ["tests/fixtures/references/generated/ordinary-unrelated-bad-annotation.dex"],
        "nonscalar": ["tests/fixtures/references/generated/nonscalar-string-035.dex"],
        "duplicate-occurrences": ["tests/fixtures/references/generated/classic-035.dex"] * 2,
    }
    records = []
    for name, paths in cases.items():
        before = [{"path":p,"bytes":(ROOT/p).stat().st_size,"sha256":hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in paths]
        result = command("native/" + name, [executable, *paths])
        require(result.returncode == 0, "tiny native fact composition failed: " + name)
        after = [hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in paths]
        require(after == [p["sha256"] for p in before], "tiny inputs changed during probe")
        native = json.loads(result.stdout)
        require(native["probe_complete"] and native["operation_status"] == "ok", "native probe lacks successful terminal")
        require(len(native["dex_occurrences"]) == len(paths), "source multiplicity mismatch")
        for source, identity in zip(native["dex_occurrences"], before):
            require(source["source"]["content_id"] == "sha256:" + identity["sha256"], "native input identity differs")
        records.append({"case":name,"inputs":before,"native_record":"artifacts/mdd-026/native/"+name+"/stdout.txt",
                        "complete_probe":True,"dex_occurrences":len(paths)})
    (OUT / "probe-inputs.json").write_text(json.dumps({"scope":"tiny isolated public API fact composition; no coverage signer or full relation provider claimed","cases":records}, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"cases":len(records),"dex_occurrences":sum(x["dex_occurrences"] for x in records),"all_probe_terminals_ok":True}))

if __name__ == "__main__": main()
