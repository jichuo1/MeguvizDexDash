"""Windows-only baseline containment; no private parsing or timing policy here.

The fixed reference SDK already requires pywin32. Its version/wheel identity is
recorded in the isolated baseline environment; this is not a production dependency.
"""
from pathlib import Path
import json
import os
import subprocess
import sys
import time
import uuid


def run_job(argv, directory, *, cwd, env, timeout_seconds, memory_bytes,
            affinity_mask, max_processes=16, max_log_bytes=16*1024*1024):
    if os.name!='nt':raise RuntimeError('this baseline supervisor is Windows-only')
    import pywintypes
    import win32api
    import win32con
    import win32event
    import win32file
    import win32job
    import win32process
    if not argv or not Path(argv[0]).is_file():raise ValueError('exact executable path required')
    if memory_bytes<=0 or affinity_mask<=0 or max_processes<=0 or timeout_seconds<=0:
        raise ValueError('positive explicit resource limits required')
    directory=Path(directory).resolve();directory.mkdir(parents=True,exist_ok=False)
    job=process=thread=None;handles=[];started=time.perf_counter();reason=None;exit_code=None
    result={'schema_version':'mdd.windows-job-run.v1','command_argv':list(map(str,argv)),
            'measurement_scope':'supervised development run; not automatically a qualified speed sample',
            'limits':{'memory_commit_bytes':str(memory_bytes),'affinity_mask':str(affinity_mask),
                      'max_processes':max_processes,'timeout_seconds':timeout_seconds,'max_log_bytes':max_log_bytes},
            'assigned_before_resume':False,'tree_empty_verified':False,'status':'launch_failed'}
    try:
        job_name='mdd-baseline-'+uuid.uuid4().hex
        job=win32job.CreateJobObject(None,job_name)
        env=dict(env);env['MDD_BASELINE_JOB_NAME']=job_name
        result['job_name']=job_name
        limits=win32job.QueryInformationJobObject(job,win32job.JobObjectExtendedLimitInformation)
        basic=limits['BasicLimitInformation'];basic['LimitFlags']=(win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|
            win32job.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION|win32job.JOB_OBJECT_LIMIT_JOB_MEMORY|
            win32job.JOB_OBJECT_LIMIT_AFFINITY|win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
        basic['Affinity']=affinity_mask;basic['ActiveProcessLimit']=max_processes;limits['JobMemoryLimit']=memory_bytes
        win32job.SetInformationJobObject(job,win32job.JobObjectExtendedLimitInformation,limits)
        security=pywintypes.SECURITY_ATTRIBUTES();security.bInheritHandle=True
        out=win32file.CreateFile(str(directory/'stdout.txt'),win32con.GENERIC_WRITE,win32con.FILE_SHARE_READ,
            security,win32con.CREATE_NEW,win32con.FILE_ATTRIBUTE_NORMAL,None)
        handles.append(out)
        err=win32file.CreateFile(str(directory/'stderr.txt'),win32con.GENERIC_WRITE,win32con.FILE_SHARE_READ,
            security,win32con.CREATE_NEW,win32con.FILE_ATTRIBUTE_NORMAL,None)
        handles.append(err)
        null=win32file.CreateFile('NUL',win32con.GENERIC_READ,win32con.FILE_SHARE_READ|win32con.FILE_SHARE_WRITE,
            security,win32con.OPEN_EXISTING,win32con.FILE_ATTRIBUTE_NORMAL,None)
        handles.append(null)
        startup=win32process.STARTUPINFO();startup.dwFlags=win32con.STARTF_USESTDHANDLES|win32con.STARTF_USESHOWWINDOW
        startup.wShowWindow=win32con.SW_HIDE;startup.hStdOutput=out;startup.hStdError=err;startup.hStdInput=null
        flags=win32con.CREATE_SUSPENDED|win32con.CREATE_NO_WINDOW|win32con.CREATE_UNICODE_ENVIRONMENT
        process,thread,pid,tid=win32process.CreateProcess(str(argv[0]),subprocess.list2cmdline(list(map(str,argv))),
            None,None,True,flags,env,str(cwd),startup)
        result['process_id']=pid
        win32job.AssignProcessToJobObject(job,process)
        if not win32job.IsProcessInJob(process,job):raise RuntimeError('worker did not enter expected Job')
        result['assigned_before_resume']=True
        win32process.ResumeThread(thread);thread.Close();thread=None
        while win32event.WaitForSingleObject(process,20)==win32con.WAIT_TIMEOUT:
            if time.perf_counter()-started>timeout_seconds:reason='timeout';break
            if sum((directory/name).stat().st_size for name in ['stdout.txt','stderr.txt'])>max_log_bytes:
                reason='log_quota';break
        if reason is None:
            exit_code=win32process.GetExitCodeProcess(process)
            active=win32job.QueryInformationJobObject(job,win32job.JobObjectBasicAccountingInformation)['ActiveProcesses']
            # Process signalling can precede job-accounting teardown (including
            # Python's venv launcher). Allow a bounded ordinary shutdown drain.
            drain=time.perf_counter()+1
            while active and time.perf_counter()<drain:
                time.sleep(.01)
                active=win32job.QueryInformationJobObject(job,win32job.JobObjectBasicAccountingInformation)['ActiveProcesses']
            if active:reason='descendant_after_root_exit'
        if reason is not None:win32job.TerminateJobObject(job,124 if reason=='timeout' else 125)
        deadline=time.perf_counter()+15
        while True:
            account=win32job.QueryInformationJobObject(job,win32job.JobObjectBasicAccountingInformation)
            if account['ActiveProcesses']==0:break
            if time.perf_counter()>=deadline:raise RuntimeError('Job did not reach ActiveProcesses=0')
            time.sleep(.01)
        win32event.WaitForSingleObject(process,15000)
        if exit_code is None:exit_code=win32process.GetExitCodeProcess(process)
        extended=win32job.QueryInformationJobObject(job,win32job.JobObjectExtendedLimitInformation)
        result.update(status='completed' if reason is None and exit_code==0 else 'failed',reason=reason,
            exit_code=exit_code,tree_empty_verified=True,
            cpu_user_seconds=account['TotalUserTime']/10_000_000,
            cpu_kernel_seconds=account['TotalKernelTime']/10_000_000,
            total_processes=account['TotalProcesses'],
            peak_job_commit_bytes=str(extended['PeakJobMemoryUsed']),
            resource_scope='all processes in the owned Job; peak commit is not RSS/PSS')
    except BaseException as error:
        result['error']=type(error).__name__+': '+str(error)
        if job is not None:
            try:win32job.TerminateJobObject(job,126)
            except Exception:pass
        if process is not None:
            try:win32api.TerminateProcess(process,126);win32event.WaitForSingleObject(process,15000)
            except Exception:pass
        raise
    finally:
        for handle in [thread,process,*handles,job]:
            if handle is not None:handle.Close()
        result['wall_seconds']=time.perf_counter()-started
        (directory/'supervisor.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    return result


def self_test(output):
    import win32api
    import win32process
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    allowed,_=win32process.GetProcessAffinityMask(win32api.GetCurrentProcess())
    mask=allowed&-allowed
    cases={
        'normal':"import win32job,win32api,os;j=win32job.OpenJobObject(win32job.JOB_OBJECT_QUERY,False,os.environ['MDD_BASELINE_JOB_NAME']);"+
            "inside=win32job.IsProcessInJob(win32api.GetCurrentProcess(),j);d=win32job.QueryInformationJobObject(j,win32job.JobObjectExtendedLimitInformation);j.Close();"+
            "flags=d['BasicLimitInformation']['LimitFlags'];"+
            "ok=inside and d['JobMemoryLimit']==536870912 and flags & win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;"+
            "print('child actual Job limits verified',ok);"+
            "exit(0 if ok else 4)",
        'timeout':"import time; time.sleep(30)",
        'descendant':"import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);print('parent ends')",
    }
    records=[]
    for name,program in cases.items():
        record=run_job([sys.executable,'-c',program],output/name,cwd=output,env=dict(os.environ),
            timeout_seconds=.5 if name=='timeout' else 10,memory_bytes=512*1024*1024,affinity_mask=mask)
        if not record['assigned_before_resume'] or not record['tree_empty_verified']:raise RuntimeError('containment not proven')
        expected={'normal':None,'timeout':'timeout','descendant':'descendant_after_root_exit'}[name]
        if record['reason']!=expected or (name=='normal' and record['status']!='completed'):
            raise RuntimeError('unexpected supervisor terminal: '+name)
        if name=='descendant' and record['total_processes']<2:raise RuntimeError('grandchild was not actually observed')
        records.append({'case':name,**record})
    (output/'summary.json').write_text(json.dumps({'status':'passed','private_input_parsed':False,'formal_measurement':False,'records':records},indent=2)+'\n',encoding='utf-8',newline='\n')
    return records


if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('usage: windows_job.py NEW_OUTPUT_DIRECTORY')
    records=self_test(sys.argv[1]);print(json.dumps({'cases':len(records),'all_jobs_empty':all(r['tree_empty_verified'] for r in records)}))
