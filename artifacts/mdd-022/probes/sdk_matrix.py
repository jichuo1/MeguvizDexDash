#!/usr/bin/env python3
"""Read-only fixed SDK format check over annotation fixture identities."""
from __future__ import annotations

import datetime
import hashlib
import json
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
SDK=Path(r"C:\Users\Administrator\AppData\Local\Android\Sdk\build-tools\37.0.0\dexdump.exe")
SDK_SHA="f870af85191214f8f59d78e6a27748f00e724bbcce362115347014419969bcce"


def require(condition,message):
    if not condition:
        raise ValueError(message)


def main():
    require(hashlib.sha256(SDK.read_bytes()).hexdigest()==SDK_SHA,"SDK identity changed")
    manifest=json.loads((ROOT/"tests/fixtures/annotations/manifest.json").read_text())
    records=[]
    for item in manifest["files"]:
        path=ROOT/item["path"]
        require(hashlib.sha256(path.read_bytes()).hexdigest()==item["sha256"],"fixture identity changed")
        argv=[str(SDK),"-f",str(path)]
        result=subprocess.run(argv,capture_output=True,text=True,timeout=30,check=False)
        expected_valid=item["expected"].startswith("valid_")
        records.append({"fixture":item["path"],"fixture_sha256":item["sha256"],"argv":argv,"exit_code":result.returncode,
            "stdout":result.stdout,"stderr":result.stderr,"expected_valid":expected_valid,"matches_expectation":(result.returncode==0)==expected_valid})
    report={"schema_version":"mdd.annotation-sdk-matrix.v1","sdk_sha256":SDK_SHA,"sdk_bytes":SDK.stat().st_size,"records":records,
        "success":all(item["matches_expectation"] for item in records),"scope":"SDK37 format verifier on synthetic DEX only; independent of the Rust reader, not installation/runtime or a compatibility profile"}
    output=HERE/"sdk-physical-items.json"
    if output.exists():
        output=HERE/("sdk-physical-items-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")+".json")
    with output.open("x",encoding="utf-8") as stream:
        stream.write(json.dumps(report,indent=2)+"\n")
    print("SDK annotation matrix:",sum(item["matches_expectation"] for item in records),"/",len(records),"matched; saved",output.name)
    for item in records:
        if not item["matches_expectation"]:
            print("difference:",Path(item["fixture"]).name,"expected_valid",item["expected_valid"],"exit",item["exit_code"],item["stderr"][:160])
    return 0 if report["success"] else 1


if __name__=="__main__":
    raise SystemExit(main())
