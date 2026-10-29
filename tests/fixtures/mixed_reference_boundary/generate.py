#!/usr/bin/env python3
"""Materialize two existing synthetic recipes for a new three-source mixed scenario."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
GENERATOR = ROOT/"tests/fixtures/references/generate.py"
RECIPES = [("classic","classic-035","076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8"),
           ("shared","shared-code-035","22eb2d4020f172334a99f5c75538af5f2b3e80673adb11803b368cc68aaec0ab")]


def main():
    spec = importlib.util.spec_from_file_location("mdd_mixed_synthetic_generator",GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = HERE/"generated"
    output.mkdir(parents=True,exist_ok=True)
    records = []
    for name,recipe,expected in RECIPES:
        raw,layout = module.build(recipe)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected:
            raise RuntimeError("frozen source recipe changed: "+name)
        path = output/(name+".dex")
        if path.exists() and path.read_bytes() != raw:
            raise RuntimeError("refusing to overwrite different fixture")
        path.write_bytes(raw)
        records.append({"id":name,"path":path.relative_to(HERE).as_posix(),"sha256":digest,"bytes":len(raw),
                        "source_recipe":recipe,"target_method_index":next(i for i,item in enumerate(layout["methods"])
                                      if item[0] == "Lfixture/A;" and item[1] == "target")})
    manifest = {"schema_version":"mdd.mixed-reference-fixtures.v1","source_generator_sha256":hashlib.sha256(GENERATOR.read_bytes()).hexdigest(),
                "scenario":["classic","shared","classic"],"files":records,
                "scope":"previous independently generated DEX recipes in a new mixed and repeated source scope; no ART/device claim"}
    text = json.dumps(manifest,indent=2)+"\n"
    target = HERE/"manifest.json"
    if target.exists() and target.read_text(encoding="utf-8") != text:
        raise RuntimeError("refusing to overwrite different fixture manifest")
    target.write_text(text,encoding="utf-8",newline="\n")
    print(json.dumps({"fixture_files":len(records),"source_occurrences":len(manifest["scenario"])}))


if __name__ == "__main__":
    main()
