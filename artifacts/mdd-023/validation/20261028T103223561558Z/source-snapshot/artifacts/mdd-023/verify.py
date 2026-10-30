"""Record finite MDD-023 checks with the repository's command recorder.

No performance measurement, external input acquisition or task qualification.
Every run directory is new; failed command records are retained.
"""
from pathlib import Path
import datetime
import hashlib
import json
import platform
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    run_id=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output=ROOT/'artifacts/mdd-023/validation'/run_id;output.mkdir(parents=True,exist_ok=False)
    owned=sorted((ROOT/'crates/mdd-dex/src/instructions').glob('*.rs'))+[ROOT/'crates/mdd-facts/src/code.rs',
        ROOT/'tests/fixtures/instructions/generate.py',ROOT/'tests/fixtures/instructions/oracle.py',
        Path(__file__).resolve(),ROOT/'tools/record_command.py']
    dependencies=[ROOT/name for name in ['Cargo.lock','rust-toolchain.toml','crates/mdd-dex/src/header.rs',
        'crates/mdd-dex/src/strings.rs','crates/mdd-dex/src/types.rs','crates/mdd-dex/src/checked_reader.rs',
        'crates/mdd-types/src/lib.rs','crates/mdd-dex/src/lib.rs','crates/mdd-facts/src/lib.rs']]
    identities=lambda paths:{p.relative_to(ROOT).as_posix():sha(p) for p in paths}
    before=identities(owned);dependency_before=identities(dependencies);commands=[];failure=None
    def run(name,argv):
        directory=output/name
        result=subprocess.run([sys.executable,str(ROOT/'tools/record_command.py'),'--output',str(directory),
            '--cwd',str(ROOT),'--quiet','--',*argv],cwd=ROOT,capture_output=True)
        record=directory/'record.json'
        if record.exists():commands.append({'name':name,'record':record.relative_to(ROOT).as_posix(),
            'exit_code':json.loads(record.read_text(encoding='utf-8'))['exit_code']})
        else:commands.append({'name':name,'record':None,'exit_code':result.returncode,
            'recording_error':result.stderr.decode(errors='replace')})
        if result.returncode:raise RuntimeError(name+' failed; original output retained')
        expected_tests={'instruction-tests':13,'code-facts-tests':2}.get(name)
        if expected_tests is not None:
            text=(directory/'stdout.txt').read_text(encoding='utf-8')
            totals=[tuple(map(int,m)) for m in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)]
            if sum(t[0] for t in totals)!=expected_tests or any(t[1] or t[2] for t in totals):
                raise RuntimeError(name+' did not run the expected non-skipped test set')
    try:
        run('generate-first',[sys.executable,'-O','tests/fixtures/instructions/generate.py'])
        fixture_dir=ROOT/'tests/fixtures/instructions/generated';first=identities(sorted(fixture_dir.iterdir()))
        run('generate-second',[sys.executable,'-O','tests/fixtures/instructions/generate.py'])
        second=identities(sorted(fixture_dir.iterdir()))
        if first!=second:raise RuntimeError('fixture regeneration is not byte reproducible')
        for path in [ROOT/'tests/fixtures/instructions/manifest.json',ROOT/'tests/fixtures/instructions/expected-results.json']:
            (output/('input-'+path.name)).write_bytes(path.read_bytes())
        run('manual-oracle',[sys.executable,'-O','tests/fixtures/instructions/oracle.py',str(output/'manual-oracle.json')])
        if (output/'manual-oracle.json').read_bytes()!=(ROOT/'tests/fixtures/instructions/expected-results.json').read_bytes():
            raise RuntimeError('independent oracle differs from frozen expected results; do not auto-update golden')
        run('instruction-tests',['cargo','test','--locked','--offline','-p','mdd-dex','instructions::','--lib','--','--nocapture'])
        run('code-facts-tests',['cargo','test','--locked','--offline','-p','mdd-facts','code::','--lib','--','--nocapture'])
        run('immutable-facts-doc-tests',['cargo','test','--locked','--offline','-p','mdd-facts','--doc'])
        run('clippy',['cargo','clippy','--locked','--offline','-p','mdd-dex','-p','mdd-facts','--all-targets','--','-D','warnings'])
        run('format',['rustfmt','--check','--edition','2024','crates/mdd-dex/src/instructions/mod.rs','crates/mdd-facts/src/code.rs'])
    except (OSError,RuntimeError,ValueError) as error:failure=str(error)
    after=identities(owned);dependency_after=identities(dependencies)
    for path in owned+dependencies:
        target=output/'source-snapshot'/path.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(path.read_bytes())
    stable=before==after and dependency_before==dependency_after
    if not stable:failure='source or dependency changed during validation; preserve run and recheck'
    oracle=json.loads((ROOT/'tests/fixtures/instructions/expected-results.json').read_text(encoding='utf-8'))
    manifest=json.loads((ROOT/'tests/fixtures/instructions/manifest.json').read_text(encoding='utf-8'))
    report={'schema_version':'mdd.instruction-conformance.v1','task':'MDD-023',
        'record_kind':'observed_component_validation','status':'passed_component_scope' if failure is None else 'failed',
        'failure':failure,'platform':platform.platform(),'source_before':before,'source_after':after,
        'dependency_before':dependency_before,'dependency_after':dependency_after,'source_stable':stable,'commands':commands,
        'fixture_manifest_sha256':sha(ROOT/'tests/fixtures/instructions/manifest.json'),
        'expected_results_sha256':sha(ROOT/'tests/fixtures/instructions/expected-results.json'),
        'opcode_vectors':manifest['opcode_vector_count'],'formats':manifest['format_count'],'reserved_rejection_vectors':32,
        'hand_operand_vectors':manifest['manual_expectation_count'],'full_dex_fixture_count':len(manifest['files']),
        'independent_fixture_valid':oracle['valid'],'independent_fixture_invalid':oracle['invalid'],
        'profile_admitted':False,'full_art_verification_complete':False,'hostlab_replacement_qualified':False,
        'performance_qualified':False,'task_done':False,
        'scope':['complete declared code-map enumeration including unreferenced items','explicit offset scope preserves order and repeats with projection budgets',
                 'same snapshot member lease for raw code/insns','all active standard opcode formats, payload/target/register/reference layouts',
                 'bounded catch/debug programs, exact pc-to-pc encoding pattern and explicit borrowed method projection'],
        'oracle_limits':['224 format vectors and opcode descriptors share AOSP table ancestry; not independent oracles',
                         'Python oracle is independently implemented for listed hand fixtures only; no full opcode/ART claim',
                         'SDK dexdump over orphan code does not prove all opcode/target semantics'],
        'remaining':['parent dependency review after MDD-020 physical item corrections','native Linux execution/CI not recorded by this local verifier',
                     'method/prototype binding, references relation graph and ART type flow are separate scopes','full HostLab corpus/equivalence/performance gates not claimed'],
        'run_directory':output.relative_to(ROOT).as_posix()}
    (output/'summary.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    (ROOT/'artifacts/mdd-023/instruction-conformance.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'status':report['status'],'run_directory':report['run_directory'],'source_stable':stable,
        'opcode_vectors':report['opcode_vectors'],'full_fixtures':report['full_dex_fixture_count'],'failure':failure},ensure_ascii=False))
    return 0 if failure is None else 1


if __name__=='__main__':raise SystemExit(main())
