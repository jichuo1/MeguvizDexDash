#!/usr/bin/env python3
"""Full raw-range/digest projection against fixed A0 and unchanged HostLab resource gate."""
from pathlib import Path
import hashlib
import json
import runpy
import subprocess
import zipfile

ROOT=Path(__file__).resolve().parents[2]
SQL=("SELECT d.entry_name,cm.method_idx,cm.access_flags,"
     "CASE WHEN ci.insns_off IS NULL THEN 'N' ELSE CAST(ci.insns_off AS TEXT) END AS insns_off,"
     "CASE WHEN ci.insns_size IS NULL THEN 'N' ELSE CAST(ci.insns_size AS TEXT) END AS insns_size "
     "FROM class_methods cm JOIN dex_files d ON d.file_id=cm.file_id "
     "LEFT JOIN code_items ci ON ci.file_id=cm.file_id AND ci.method_idx=cm.method_idx "
     "ORDER BY cm.file_id,cm.method_idx")


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def require(condition,message):
    if not condition:raise ValueError(message)


def main():
    native_path=ROOT/'artifacts/mdd-025/raw-fingerprints/public-newpipe/stdout.txt'
    native=json.loads(native_path.read_bytes())
    require(native['calculation_complete'] and not native['full_audit_complete'],'native scope not complete/correct')
    registry=json.loads((ROOT/'conformance/manifests/engine-binaries.json').read_text(encoding='utf8'))
    reference=next(x for x in registry['binaries'] if x['group']=='A0' and x['platform']=='windows_amd64')
    binary=Path(reference['actual_path']);apk=ROOT/'artifacts/local/inputs/NewPipe_v0.28.6.apk'
    sha='e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58'
    require(digest(binary)==reference['expected_sha256'] and digest(apk)==sha,'engine/input identity differs')
    output=ROOT/'artifacts/mdd-025/raw-fingerprints/independent-public';output.mkdir(parents=True,exist_ok=True)
    argv=[str(binary),'--threads','1','query','--input',str(apk),'--sql',SQL]
    run=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=120,check=False)
    (output/'reference-stdout.txt').write_bytes(run.stdout);(output/'reference-stderr.txt').write_bytes(run.stderr)
    require(run.returncode==0 and len(run.stdout)<64*1024*1024,'reference query failed or result budget exceeded')
    table=[]
    for line in run.stdout.decode('utf8','strict').splitlines():
        line=line.strip()
        if line.startswith('|') and line.endswith('|'):table.append([x.strip() for x in line[1:-1].split('|')])
    require(table and table[0]==['entry_name','method_idx','access_flags','insns_off','insns_size'],'reference schema differs')
    by_member={};seen=set();raw_dexes={}
    with zipfile.ZipFile(apk) as archive:
        for row in table[1:]:
            require(len(row)==5,'ambiguous reference row')
            name,method,flags,off,size=row;method=int(method);flags=int(flags)
            require((name,method) not in seen,'duplicate logical method row');seen.add((name,method))
            if off=='N':
                require(size=='N','no body interval dimensions disagree')
                kind='native_no_body' if flags&0x100 else 'abstract_no_body' if flags&0x400 else None
                require(kind is not None,'reference lost a concrete body')
                record={'body_kind':kind,'insns_off':None,'insns_size':None,'method_idx':method,'sha256':None}
            else:
                off=int(off);size=int(size)
                data=raw_dexes.setdefault(name,archive.read(name)) if name not in raw_dexes else raw_dexes[name]
                require(off>=0 and size>=0 and off%2==0 and off+size*2<=len(data),'reference raw interval out of bounds')
                record={'body_kind':'present','insns_off':str(off),'insns_size':str(size),'method_idx':method,
                    'sha256':hashlib.sha256(data[off:off+size*2]).hexdigest()}
            by_member.setdefault(name,[]).append(record)
        native_checks=[]
        members=archive.infolist()
        for item in native['selected_dexes']:
            ordinal=int(item['member_id'].split(':member:')[1]);name=members[ordinal].filename
            require('sha256:'+hashlib.sha256(archive.read(members[ordinal])).hexdigest()==item['content_id'],'physical member content mismatch')
            rows=sorted(by_member[name],key=lambda row:row['method_idx'])
            canonical=json.dumps(rows,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf8')
            actual=hashlib.sha256(canonical).hexdigest()
            require(len(rows)==item['method_count'] and actual==item['canonical_method_evidence_sha256'],'full method byte evidence differs: '+name)
            native_checks.append({'entry_name':name,'method_rows':len(rows),'canonical_sha256':actual,'equal':True})
    legacy=ROOT/'artifacts/local/hostlab-reference/tools/hostlab/audit_common.py'
    resource_gate=runpy.run_path(str(legacy))['resource_fingerprints']
    legacy_resources=resource_gate(apk)
    require(legacy_resources==native['resource_fingerprints'],'legacy raw resource fingerprints differ')
    require(digest(apk)==sha and digest(binary)==reference['expected_sha256'],'input/engine changed during comparison')
    result={'record_kind':'observed_full_raw_evidence_projection','reference_argv':argv,'reference_exit_code':run.returncode,
        'reference_engine_sha256':digest(binary),'input_sha256':sha,'native_summary_sha256':digest(native_path),
        'method_checks':native_checks,'complete_method_rows':len(table)-1,'resource_entries':len(legacy_resources),
        'legacy_resource_gate_sha256':digest(legacy),'legacy_resource_gate_commit':'8782f43d537c442905123e35af325c412caa5188',
        'raw_resource_equal':True,'all_byte_projections_equal':True,
        'scope':'full raw insns off/size/SHA and no-body state, plus unchanged legacy selected raw resources; not full business/ART/SQL/performance qualification'}
    (output/'comparison.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
