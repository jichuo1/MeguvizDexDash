#!/usr/bin/env python3
"""Independent count projection only; no full-result or performance qualification."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
SQL = ('SELECT d.entry_name,(SELECT count(*) FROM strings s WHERE s.string_pool_id=d.string_pool_id) AS string_rows,'
       '(SELECT count(*) FROM types t WHERE t.file_id=d.file_id) AS type_rows,'
       '(SELECT count(*) FROM protos p WHERE p.file_id=d.file_id) AS proto_rows FROM dex_files d ORDER BY d.file_id')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    references = json.loads((ROOT/'conformance/manifests/engine-binaries.json').read_text(encoding='utf-8'))
    reference = next(x for x in references['binaries'] if x['group']=='A0' and x['platform']=='windows_amd64')
    binary = Path(reference['actual_path'])
    apk = ROOT/'artifacts/local/inputs/NewPipe_v0.28.6.apk'
    expected_sha = 'e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58'
    if digest(binary) != reference['expected_sha256'] or digest(apk) != expected_sha:
        raise ValueError('reference/input byte identity differs')
    argv = [str(binary),'--threads','1','query','--input',str(apk),'--sql',SQL]
    run = subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=60,check=False)
    if run.returncode or len(run.stdout)>65536:
        raise ValueError('reference count query failed or exceeded response budget')
    columns = ['entry_name','string_rows','type_rows','proto_rows']
    table = []
    for line in run.stdout.decode('utf-8','strict').splitlines():
        line=line.strip()
        if line.startswith('|') and line.endswith('|'):
            table.append([cell.strip() for cell in line[1:-1].split('|')])
    if not table or table[0] != columns or len(table)!=3:
        raise ValueError('reference result schema/rows differ from expected projection')
    rows = {row[0]:{'strings':int(row[1]),'types':int(row[2]),'prototypes':int(row[3])} for row in table[1:]}
    actual = json.loads((ROOT/'artifacts/mdd-020/public-newpipe-metadata.json').read_text(encoding='utf-8'))
    if actual['input_sha256'] != expected_sha or not actual['result']['metadata_calculation_complete']:
        raise ValueError('native evidence does not bind the complete metadata input')
    summary=actual['result']['selected_dexes']
    # Map by verified physical member ordinal, not an assumed cross-engine file_id.
    native = {}
    import zipfile
    with zipfile.ZipFile(apk) as archive:
        members=archive.infolist()
        for item in summary:
            ordinal=int(item['dex_occurrence_id'].split(':member:')[1].split(':')[0])
            member=members[ordinal]
            if 'sha256:'+hashlib.sha256(archive.read(member)).hexdigest()!=item['content_id']:
                raise ValueError('native occurrence content does not match physical APK member')
            native[member.filename]={key:item[key] for key in ['strings','types','prototypes']}
    if rows != native or digest(apk)!=expected_sha:
        raise ValueError('independent count projection/source identity mismatch')
    output=ROOT/'artifacts/mdd-020/public-reference-counts'
    output.mkdir(parents=True,exist_ok=True)
    (output/'stdout.txt').write_bytes(run.stdout)
    (output/'stderr.txt').write_bytes(run.stderr)
    result={'record_kind':'observed_independent_count_projection','argv':argv,'exit_code':run.returncode,
        'input_sha256':expected_sha,'reference_binary_sha256':digest(binary),'native_evidence':'artifacts/mdd-020/public-newpipe-metadata.json',
        'reference_rows':rows,'native_rows':native,'equivalent_for_this_projection':True,
        'stdout_sha256':hashlib.sha256(run.stdout).hexdigest(),
        'scope':'count projection over both physical DEX members only; no full value/NULL/order/multiplicity/HostLab/performance qualification'}
    (output/'comparison.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'count_projection_equal':True,'rows':rows,'full_audit_qualified':False}))


if __name__=='__main__':
    main()
