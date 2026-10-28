"""Unmodified HostLab local-audit consumer with an explicit A1 binary pin adapter.

Preflight never parses an APK. --run requires a root-owned measurement lease.
No upstream source, installer, real config, AI, Telegram or remote state is edited.
"""
from pathlib import Path
import argparse
import datetime
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import types

ROOT=Path(__file__).resolve().parents[3]
REFERENCE_COMMIT='8782f43d537c442905123e35af325c412caa5188'
EVIDENCE_KEYS={'class_records','discoveries','families','features','gates','home_probe_sha256','invoke_edges',
    'limitations','page_path_matrix','protocol_definitions','protocol_paths','protocol_twins',
    'resource_fingerprints','rule_sha256','rule_version','sample','scope','unclassified_protocol_callers',
    'unknown_families','unregistered_protocols'}
MULTISETS={'class_records','invoke_edges','protocol_definitions','protocol_twins','unclassified_protocol_callers','discoveries'}


def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        while block:=stream.read(1024*1024):h.update(block)
    return h.hexdigest()


def read(path):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('duplicate JSON key: '+key)
            result[key]=value
        return result
    def nonfinite(value):raise ValueError('non-finite JSON constant: '+value)
    return json.loads(Path(path).read_text(encoding='utf-8'),object_pairs_hook=unique,parse_constant=nonfinite)


def write(path,value):
    Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')


def variant(plan,name):
    item=next((v for v in plan['variants'] if v['id']==name),None)
    if not item or name not in ('A0','A1'):raise ValueError('only explicit A0/A1 native consumers are implemented')
    return item


def source_identity(plan):
    reference=Path(plan['reference']['path']).resolve()
    head=subprocess.check_output(['git','-c','safe.directory='+str(reference),'-C',str(reference),'rev-parse','HEAD'],text=True).strip()
    dirty=subprocess.check_output(['git','-c','safe.directory='+str(reference),'-C',str(reference),'status','--porcelain'],text=True)
    changed=subprocess.run(['git','-c','core.autocrlf=false','-c','safe.directory='+str(reference),'-C',str(reference),
        'diff','HEAD','--quiet'],capture_output=True).returncode
    if head!=REFERENCE_COMMIT or changed or any(line.startswith('??') for line in dirty.splitlines()):
        raise RuntimeError('fixed reference has commit/content or untracked-source changes')
    expected=read(ROOT/plan['reference']['source_manifest'])['source_files']
    for relative,identity in expected.items():
        if digest(reference/relative)!=identity['sha256']:raise RuntimeError('reference tool changed: '+relative)
    return reference


def check_lease(path,plan):
    if not path:raise RuntimeError('root exclusive resource lease is required before private parsing')
    lease=read(path);now=datetime.datetime.now(datetime.timezone.utc)
    starts=datetime.datetime.fromisoformat(lease['starts_utc'].replace('Z','+00:00'))
    expiry=datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z','+00:00'))
    if lease.get('owner')!='root' or lease.get('task')!='MDD-005' or lease.get('status')!='active' or expiry<=now or starts>now:
        raise RuntimeError('lease owner/task/state/expiry is invalid')
    if not lease.get('exclusive') or lease.get('cpu_affinity_mask')!=plan['resource_request']['cpu_affinity_mask']:
        raise RuntimeError('exclusive resource identity differs from pre-registered plan')
    return lease


def preflight(plan):
    blockers=[];facts={'private_input_parsed':False,'formal_measurement':False,'platform':platform.platform()}
    try:
        reference=source_identity(plan);facts['reference_commit']=REFERENCE_COMMIT
        sys.dont_write_bytecode=True;sys.path.insert(0,str(reference/'tools/hostlab'))
        import analyze,hostlab,verify_audits
        from analysis.run_intake import EXPECTED_FEATURES
        facts['feature_names']=list(EXPECTED_FEATURES);facts['feature_count']=len(EXPECTED_FEATURES)
        facts['evidence_keys']=sorted(EVIDENCE_KEYS);facts['tool_hashes']=analyze.tool_hashes()
        if len(EXPECTED_FEATURES)!=27:raise RuntimeError('fixed FEATURE contract differs')
        facts['sdk_tools']={name:str(hostlab.sdk_tool(name)) for name in ['aapt','apksigner']}
        facts['sdk_tool_hashes']={name:digest(path) for name,path in facts['sdk_tools'].items()}
        facts['java']=str(Path(subprocess.check_output(['where.exe','java'],text=True).splitlines()[0]))
        facts['java_sha256']=digest(facts['java'])
        facts['mcp_version']=importlib.metadata.version('mcp')
        if facts['mcp_version']!='2.2.0':raise RuntimeError('fixed MCP version not installed')
        for name in ['A0','A1']:
            item=variant(plan,name);binary=Path(item['engine_binary']['path'])
            if digest(binary)!=item['engine_binary']['sha256']:raise RuntimeError(name+' binary changed')
            result=subprocess.run([str(binary),'--version'],capture_output=True,text=True,timeout=10)
            if result.returncode or item['version'] not in result.stdout:raise RuntimeError(name+' version probe failed')
            facts[name]={'version_stdout':result.stdout.strip(),'sha256':digest(binary)}
        receipt=read(ROOT/plan['resource_request']['supervisor_smoke'])
        if receipt.get('status')!='passed' or any(not r['tree_empty_verified'] for r in receipt['records']):
            raise RuntimeError('Windows Job supervision proof missing')
        facts['windows_job_smoke']='passed; suspended assignment, timeout and descendant cleanup'
        for item in plan['inputs']:
            stat=Path(item['path']).stat()
            if str(stat.st_size)!=item['bytes'] or stat.st_mtime_ns!=item['verified_mtime_ns']:
                raise RuntimeError('input stat differs from actual SHA acquisition receipt: '+item['occurrence_id'])
        facts['input_identity_basis']='root full-SHA receipts + unchanged stat; each actual run must fully rehash before/after'
    except (OSError,RuntimeError,ValueError,ImportError,StopIteration,subprocess.SubprocessError) as error:
        blockers.append(type(error).__name__+': '+str(error))
    technical_ready=not blockers
    denial=None
    denial_path=plan['resource_request'].get('current_root_denial')
    if denial_path:
        denial=read(ROOT/denial_path)
        if denial.get('decision')=='lease_not_granted':
            blockers.append('root measured available physical '+denial['available_physical_bytes']+' bytes < '+denial['required_physical_bytes']+'; no private worker admitted')
    blockers.extend(['root exclusive CPU/memory/time window not yet granted',
        'full private A0/A1 results and 20-group equality certificate not yet executed',
        'A2 compact MCP transport candidate not admitted for the full audit consumer'])
    return {'schema_version':'mdd.hostlab-baseline-preflight.v1','status':('blocked_by_resource_window' if denial else 'ready_for_qualification_window') if technical_ready else 'blocked',
        'technical_preparation_ready':technical_ready,'root_resource_observation':denial,
        'formal_performance_ready':False,'facts':facts,'blockers':blockers}


def canonical_groups(evidence):
    if set(evidence)!=EVIDENCE_KEYS:raise RuntimeError('complete 20-group evidence contract differs')
    groups={}
    for key,value in evidence.items():
        value=json.loads(json.dumps(value,ensure_ascii=False,allow_nan=False))
        if key in MULTISETS:value=sorted(json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False) for v in value)
        encoded=json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
        groups[key]={'sha256':hashlib.sha256(encoded).hexdigest(),'count':len(value) if isinstance(value,(dict,list,tuple)) else None}
    return groups


def compare_certificates(left,right):
    for item in [left,right]:
        if (item.get('complete') is not True or item.get('evidence_group_count')!=20
            or item.get('feature_count')!=27 or item.get('fallback_count')!=0
            or item.get('output_fully_materialized') is not True or item.get('more_available') is not False
            or item.get('truncated') is not False or set(item.get('groups',{}))!=EVIDENCE_KEYS):
            raise RuntimeError('certificate has incomplete work, coverage, consumer output or fallback')
    if (left['input_sha256']!=right['input_sha256'] or left['reference_source_commit']!=right['reference_source_commit']
        or left['tools']!=right['tools']):raise RuntimeError('paired input/source/consumer identity differs')
    checks={key:left['groups'][key]==right['groups'][key] for key in sorted(EVIDENCE_KEYS)}
    return {'all_equal':all(checks.values()),'group_count':20,'checks':checks,
            'mismatch_groups':[key for key,value in checks.items() if not value],
            'performance_qualified':False,'scope':'complete same-input evidence equality only'}


def pin_provider(original,selected):
    """A1-only provider adapter. Original pinned installer source is unchanged."""
    binary=Path(selected['engine_binary']['path']).resolve();expected=selected['engine_binary']['sha256']
    proxy=types.ModuleType('mdd_baseline_explicit_a1_pin')
    proxy.__file__=__file__;proxy.VERSION=selected['version']
    def verify(path=None):
        actual=Path(path).resolve() if path is not None else binary
        if actual!=binary or digest(actual)!=expected:raise RuntimeError('explicit A1 provider identity mismatch')
        return actual
    def status():
        try:verify();return {'available':True,'version':selected['version'],'sha256':expected,'path':str(binary),
            'pin_provider':'mdd-baseline-explicit-a1-v1','baseline_variant':'A1'}
        except (OSError,RuntimeError) as error:return {'available':False,'version':selected['version'],'reason':str(error)}
    proxy.verify=verify;proxy.status=status;proxy.executable=lambda:binary
    proxy.asset=lambda:(binary.name,expected)
    proxy.install=lambda:(_ for _ in ()).throw(RuntimeError('baseline adapter never installs or renews an engine'))
    return proxy


def run(plan,selected,sample,output,lease_path):
    check_lease(lease_path,plan);reference=source_identity(plan);output=Path(output).resolve()
    import win32api,win32job
    job_name=os.environ.get('MDD_BASELINE_JOB_NAME')
    if not job_name:raise RuntimeError('worker was not launched by the owned Job supervisor')
    query_job=win32job.OpenJobObject(win32job.JOB_OBJECT_QUERY,False,job_name)
    try:
        if not win32job.IsProcessInJob(win32api.GetCurrentProcess(),query_job):raise RuntimeError('worker is not in the expected owned Job')
        limits=win32job.QueryInformationJobObject(query_job,win32job.JobObjectExtendedLimitInformation)
    finally:query_job.Close()
    expected_resources=plan['resource_request']
    if (limits['JobMemoryLimit']!=int(expected_resources['job_memory_commit_bytes'])
        or limits['BasicLimitInformation']['Affinity']!=int(expected_resources['cpu_affinity_mask'])
        or not limits['BasicLimitInformation']['LimitFlags']&win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE):
        raise RuntimeError('actual worker Job does not match the root-leased memory/affinity containment')
    output.relative_to(ROOT/'artifacts/local');output.mkdir(parents=True,exist_ok=False)
    apk=Path(sample['path']).resolve(strict=True)
    if str(apk.stat().st_size)!=sample['bytes'] or digest(apk)!=sample['sha256']:
        raise RuntimeError('private input does not match pinned actual acquisition')
    sys.dont_write_bytecode=True;sys.path.insert(0,str(reference/'tools/hostlab'))
    import install_dexsql as original
    binary=Path(selected['engine_binary']['path']).resolve()
    if digest(binary)!=selected['engine_binary']['sha256']:raise RuntimeError('selected engine changed')
    os.environ['HOSTLAB_DEXSQL']=str(binary)
    if selected['id']=='A1':sys.modules['install_dexsql']=pin_provider(original,selected)
    import analyze,hostlab,verify_audits
    from analysis.run_intake import EXPECTED_FEATURES
    hostlab.STATE=output/'state';hostlab.CONFIG=hostlab.STATE/'config.json'
    os.environ['DEXQ_CACHE_DIR']=str(output/'cache');os.environ['PYTHONIOENCODING']='utf-8'
    os.environ['PYTHONDONTWRITEBYTECODE']='1'
    def forbidden(*_,**__):raise RuntimeError('baseline forbids remote/config/AI/publish entry points')
    for name in ['config','api_private','manifest','select']:setattr(hostlab,name,forbidden)
    old_connect=socket.socket.connect
    def offline_connect(sock,address):
        if sock.family in (socket.AF_INET,socket.AF_INET6):raise RuntimeError('baseline Python network access forbidden')
        return old_connect(sock,address)
    socket.socket.connect=offline_connect
    tools_before=analyze.tool_hashes();carrier={};started=time.perf_counter()
    # Keep the real business consumer, full FEATURE set, intake and home gates.
    rc=analyze.main(['audit','--apk',str(apk),'--mode','full','--backend','dexsql',
                     '--timeout',str(plan['resource_request']['native_timeout_seconds'])],surface_output=carrier)
    summaries=list((hostlab.STATE/'reports').glob('*/*/*/summary.json'))
    if len(summaries)!=1:raise RuntimeError('not exactly one fresh complete report')
    report=read(summaries[0]);native=report.get('native_audit',{})
    if (rc not in (0,1) or report.get('audit_complete') is not True or report.get('mode')!='full'
        or report.get('audit_backend')!='dexsql' or report.get('backend_fallback_reason') is not None
        or report.get('home_probe_exit_code')!=0 or set(report.get('features',{}))!=set(EXPECTED_FEATURES)
        or native.get('complete') is not True or native.get('source_sha_reverified') is not True
        or report['sample'].get('sha256')!=sample['sha256']):raise RuntimeError('full audit/identity/fallback gates failed')
    if type(native.get('class_count')) is not int or native['class_count']<=0 or type(native.get('queries')) is not int or native['queries']<=0:
        raise RuntimeError('fixed full BIL audit did not consume positive class/query work')
    if native.get('native',{}).get('sha256')!=selected['engine_binary']['sha256'] or native.get('native',{}).get('version')!=selected['version']:
        raise RuntimeError('actual native consumer engine identity differs from selected A0/A1')
    expected_cert=sample['expected_certificate_sha256']
    if report['sample'].get('certificate_sha256')!=expected_cert:raise RuntimeError('actual signer lineage differs')
    surface=carrier.get('report')
    if not isinstance(surface,dict):raise RuntimeError('full native surface report was not consumed')
    if surface.get('scan_execution',{}).get('dex_files')!=sample['dex_members']:
        raise RuntimeError('full physical DEX input coverage differs from root acquisition')
    surface['sample']=report['sample'];features=summaries[0].with_name('features.tsv')
    if 'META\taudit_complete\ttrue' not in features.read_text(encoding='utf-8').splitlines():raise RuntimeError('missing final FEATURE marker')
    if digest(apk)!=sample['sha256'] or tools_before!=analyze.tool_hashes():raise RuntimeError('source/input identity changed')
    evidence=verify_audits.evidence(report,surface,features,summaries[0].with_name('home-frame.log'))
    hostlab.write_json(output/'evidence.json',evidence)
    elapsed=time.perf_counter()-started
    groups=canonical_groups(evidence)
    certificate={'schema_version':'mdd.hostlab-complete-certificate.v1','complete':True,'variant':selected['id'],
        'input_sha256':sample['sha256'],'engine_sha256':selected['engine_binary']['sha256'],'engine_version':selected['version'],
        'reference_source_commit':REFERENCE_COMMIT,'tools':tools_before,'provider_adapter_sha256':digest(__file__) if selected['id']=='A1' else None,
        'feature_count':len(EXPECTED_FEATURES),'evidence_group_count':len(groups),'groups':groups,
        'fallback_count':0,'output_fully_materialized':True,'more_available':False,'truncated':False,
        'source_positions_runtime_verified':False,'business_exit_code':rc,'evidence_sha256':digest(output/'evidence.json'),
        'timing':{'wall_seconds':elapsed,'boundary':'local analyze.main full native+surface, retained intake/home gates, post-input SHA and evidence JSON publication; certificate hashing excluded',
                  'difference_from_historical':'explicit local APK identity SDK/copy is included; no HF metadata/download path, not directly the historical Linux E'},
        'native_phases':native.get('phases'),'queries':native.get('queries')}
    certificate['class_count']=native['class_count']
    source_identity(plan);write(output/'certificate.json',certificate)
    print(json.dumps({'complete':True,'certificate':str(output/'certificate.json'),'certificate_sha256':digest(output/'certificate.json'),
        'variant':selected['id'],'full_audit_static_only':True,'runtime_verified':False}))


def launch(plan,args):
    """One explicitly leased qualification run; no implicit trial loops."""
    lease=check_lease(args.lease,plan)
    from windows_job import run_job
    output=args.output.resolve();output.relative_to(ROOT/'artifacts/local')
    output.mkdir(parents=True,exist_ok=False)
    env={key:value for key,value in os.environ.items() if not re.search(r'TOKEN|SECRET|PASSWORD|API_KEY',key,re.I)}
    env.update(PYTHONDONTWRITEBYTECODE='1',PYTHONIOENCODING='utf-8')
    for name in ['tmp','cache']:(output/name).mkdir()
    env.update(TEMP=str(output/'tmp'),TMP=str(output/'tmp'),DEXQ_CACHE_DIR=str(output/'cache'),XDG_CACHE_HOME=str(output/'cache'))
    resources=plan['resource_request']
    import ctypes
    import win32api,win32process
    allowed,_=win32process.GetProcessAffinityMask(win32api.GetCurrentProcess())
    if int(resources['cpu_affinity_mask'])&~allowed:raise RuntimeError('leased CPU mask is unavailable')
    class Memory(ctypes.Structure):
        _fields_=[('length',ctypes.c_uint32),('load',ctypes.c_uint32)]+[(name,ctypes.c_uint64) for name in ['total','available','page_total','page_available','virtual_total','virtual_available','extended']]
    memory=Memory();memory.length=ctypes.sizeof(memory)
    memory_ok=ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory))
    if not memory_ok or memory.available<int(resources['minimum_free_memory_bytes']):
        write(output/'admission-blocked.json',{'reason':'insufficient_measured_free_memory','captured_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'available_physical_bytes':str(memory.available) if memory_ok else None,'required_bytes':resources['minimum_free_memory_bytes'],
            'worker_started':False,'private_input_parsed':False})
        raise RuntimeError('root window has insufficient measured free memory; do not start a private run')
    remaining=(datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z','+00:00'))-datetime.datetime.now(datetime.timezone.utc)).total_seconds()-15
    if remaining<=0:raise RuntimeError('lease has no remaining worker/cleanup deadline')
    argv=[plan['python']['path'],'-B',str(Path(__file__).resolve()),'--manifest',str(args.manifest.resolve()),
        '--run','--variant',args.variant,'--sample',args.sample,'--output',str(output/'worker'),'--lease',str(args.lease.resolve())]
    result=run_job(argv,output/'job',cwd=ROOT,env=env,
        timeout_seconds=min(resources['worker_timeout_seconds'],remaining),memory_bytes=int(resources['job_memory_commit_bytes']),
        affinity_mask=int(resources['cpu_affinity_mask']),max_processes=resources['max_processes'])
    complete=result['status']=='completed' and result['tree_empty_verified']
    certificate=None
    if complete:
        path=output/'worker/certificate.json'
        if not path.is_file():raise RuntimeError('worker exited without its complete certificate')
        certificate=read(path)
        if certificate.get('complete') is not True or certificate.get('evidence_group_count')!=20:
            raise RuntimeError('incomplete consumer certificate')
        evidence=output/'worker/evidence.json'
        if digest(evidence)!=certificate.get('evidence_sha256') or canonical_groups(read(evidence))!=certificate.get('groups'):
            raise RuntimeError('parent full evidence consumption differs from worker certificate')
    receipt={'schema_version':'mdd.hostlab-qualification-run.v1','record_kind':'observed_qualification_not_formal_performance',
        'variant':args.variant,'sample':args.sample,'complete':complete,'supervisor':str(output/'job/supervisor.json'),
        'certificate':str(output/'worker/certificate.json') if certificate else None,
        'equivalence':'not_compared','formal_performance_qualified':False}
    write(output/'qualification-receipt.json',receipt);print(json.dumps(receipt,ensure_ascii=False));return 0 if complete else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--preflight',action='store_true');parser.add_argument('--run',action='store_true');parser.add_argument('--launch',action='store_true')
    parser.add_argument('--variant',choices=['A0','A1']);parser.add_argument('--sample');parser.add_argument('--output',type=Path);parser.add_argument('--lease',type=Path)
    args=parser.parse_args();plan=read(args.manifest)
    if args.preflight:
        result=preflight(plan)
        if args.output:write(args.output,result)
        print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if result['status']=='ready_for_qualification_window' else 2
    if args.launch:
        if not args.variant or not args.sample or args.output is None:parser.error('leased launch requires variant/sample/output')
        return launch(plan,args)
    if not args.run or not args.variant or not args.sample or args.output is None:parser.error('explicit --preflight or leased --run/variant/sample/output required')
    sample=next((x for x in plan['inputs'] if x['occurrence_id']==args.sample),None)
    if sample is None:raise ValueError('unknown pinned sample')
    run(plan,variant(plan,args.variant),sample,args.output,args.lease);return 0


if __name__=='__main__':raise SystemExit(main())
