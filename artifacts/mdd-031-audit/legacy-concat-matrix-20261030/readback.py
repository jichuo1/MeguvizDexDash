#!/usr/bin/env python3
"""Check fixed CLI results against per-operand UTF-8 replacement and UTF-16 MUTF-8 oracle."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent

def require(value,reason):
    if not value:raise RuntimeError(reason)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def units(value):
    if isinstance(value,list):return value
    if isinstance(value,bytes):value=value.decode('utf8',errors='replace')
    raw=value.encode('utf-16-le',errors='surrogatepass')
    return [int.from_bytes(raw[i:i+2],'little') for i in range(0,len(raw),2)]
def mutf8(values):
    out=bytearray()
    for u in values:
        if u==0:out.extend((0xc0,0x80))
        elif u<0x80:out.append(u)
        elif u<0x800:out.extend((0xc0|(u>>6),0x80|(u&63)))
        else:out.extend((0xe0|(u>>12),0x80|((u>>6)&63),0x80|(u&63)))
    return out.hex().upper()
def main():
    require(len(sys.argv)==2,'usage: readback.py RUN_NAME')
    run=(HERE/'runs'/sys.argv[1]).resolve();require(run.parent==(HERE/'runs').resolve(),'invalid run')
    report=json.loads((run/'report.json').read_text(encoding='utf8'))
    require(report['status']=='observed_all' and report['identities_unchanged'],'incomplete run')
    require(not report['profile_admitted'] and not report['task_complete_proven'],'scope overstated')
    require(sha(HERE/'run.py')==report['script_sha256'],'runner identity')
    require(sha(ROOT/'artifacts/mdd-005/preparation-20261028/windows_job.py')==report['supervisor_sha256'],'supervisor identity')
    require(report['identities_before']==report['identities_after'],'identity drift')
    for key,item in report['identities_before'].items():
        require(item['matches'] and sha(Path(item['path']))==item['sha256']==item['expected_sha256'],key+' identity')
    inputs={
      'ascii':(b'A',b'B'), 'valid_utf8':(b'\xc3\xa9',b'A'), 'split_utf8':(b'\xc3',b'\xa9'),
      'split_supplementary':(b'\xf0\x9f',b'\x98\x80'), 'truncated_prefix':(b'\xe2\x82',b'A'),
      'invalid_continuation':(b'\xc3A',b'B'), 'two_invalid':(b'\xff',b'\xff'),
      'overlong_nul':(b'\xc0\x80',b'A'), 'blob_text':(b'A','B'), 'text_blob':('B',b'A'),
      'blob_unicode_text':(b'A','中'), 'null_right':(b'A',None), 'null_left':(None,b'A'),
      'source_nul':([0],b'A'), 'source_surrogate':([0xd800],b'A'), 'source_pair':([0xd83d,0xde00],b'A')}
    expected={}
    for name,(left,right) in inputs.items():
        expected[name]={'result_type':'null','result_hex':''} if left is None or right is None else {
           'result_type':'text','result_hex':mutf8(units(left)+units(right))}
    seen=set()
    for item in report['cases']:
        key=(item['engine'],item['case']);require(key not in seen and key[0] in ('A0','A1') and key[1] in inputs,'case key');seen.add(key)
        require(item['status']=='observed' and int(item['available_physical_bytes'])>=3*1024**3,str(key)+' admission')
        folder=run/(key[0]+'-'+key[1])
        for name in ('stdout','stderr','supervisor'):
            extension='.json' if name=='supervisor' else '.txt'
            require(sha(folder/(name+extension))==item[name+'_sha256'],str(key)+' '+name)
        job=json.loads((folder/'supervisor.json').read_text(encoding='utf8'))
        require(job==item['job'] and job['status']=='completed' and job['exit_code']==0
            and job['assigned_before_resume'] and job['tree_empty_verified'],str(key)+' job')
        require(job['limits']['memory_commit_bytes']==str(2*1024**3) and job['limits']['timeout_seconds']==90
            and job['limits']['affinity_mask']=='15',str(key)+' job limits')
        rows=[[v.strip() for v in line.strip('|').split('|')] for line in (folder/'stdout.txt').read_text(encoding='utf8').splitlines() if line.startswith('|')]
        require(len(rows)==2 and rows[0]==['result_type','result_hex'] and len(rows[1])==2,str(key)+' table')
        cells=dict(zip(rows[0],rows[1]));require(cells==expected[key[1]] and item['table']=={'status':'one_row','cells':cells},str(key)+' oracle mismatch')
    require(seen=={(engine,case) for engine in ('A0','A1') for case in inputs},'matrix denominator')
    result={'status':'passed_scoped_readback','cases':len(seen),'oracle':'per operand Python UTF-8 replacement then UTF-16 unit MUTF-8 encoding',
        'expected':expected,'report_sha256':sha(run/'report.json'),'runner_sha256':sha(HERE/'run.py'),
        'readback_sha256':sha(Path(__file__)),'profile_admitted':False,'task_complete_proven':False,
        'scope':'fixed legacy CLI on one synthetic DEX; oracle matches measured cases only; not complete dialect or performance qualification'}
    (run/'readback.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'status':result['status'],'cases':len(seen)}))
if __name__=='__main__':main()
