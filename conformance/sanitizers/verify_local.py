"""Record real stable commands and source identity before/after a bounded local smoke."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def snapshot():
    paths = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', ROOT / 'rust-toolchain.toml']
    for directory in ('crates/mdd-types', 'crates/mdd-dex', 'crates/mdd-input', 'fuzz',
                      'conformance/sanitizers'):
        paths += [p for p in (ROOT / directory).rglob('*') if p.is_file()
                  and p.suffix in ('.rs', '.toml', '.lock', '.py', '.json')
                  and not {'target', '__pycache__'}.intersection(p.relative_to(ROOT).parts)]
    paths.append(ROOT / '.github/workflows/parser-safety.yml')
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(paths))}


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'artifacts/conformance/parser-safety/local' / stamp
    out.mkdir(parents=True, exist_ok=False)
    before = snapshot()
    (out / 'sources-before.json').write_text(json.dumps(before, indent=2) + '\n', encoding='utf-8', newline='\n')
    commands = [
        ('compiler', ['rustc', '-Vv']),
        ('tests', ['cargo', 'test', '--manifest-path', 'fuzz/Cargo.toml', '--locked', '--lib']),
        ('clippy', ['cargo', 'clippy', '--manifest-path', 'fuzz/Cargo.toml', '--locked', '--lib',
                    '--bin', 'mutation-smoke', '--', '-D', 'warnings']),
        ('format', ['cargo', 'fmt', '--manifest-path', 'fuzz/Cargo.toml', '--', '--check']),
        ('driver-contract', [sys.executable, '-O', 'conformance/sanitizers/test_runner.py']),
        ('smoke', ['cargo', 'run', '--manifest-path', 'fuzz/Cargo.toml', '--locked', '--bin',
                   'mutation-smoke', '--', 'fuzz/corpus', '64']),
    ]
    result = []
    for name, argv in commands:
        completed = subprocess.run([sys.executable, 'tools/record_command.py', '--quiet', '--output',
                                    str(out / name), '--'] + argv, cwd=ROOT, timeout=180)
        result.append({'name': name, 'exit_code': completed.returncode})
        if completed.returncode:
            break
    after = snapshot()
    stable = before == after
    (out / 'sources-after.json').write_text(json.dumps(after, indent=2) + '\n', encoding='utf-8', newline='\n')
    binary = ROOT / 'fuzz/target/debug' / ('mutation-smoke.exe' if sys.platform == 'win32' else 'mutation-smoke')
    summary = dict(schema_version='mdd.parser-local-validation.v1', source_stable=stable,
                   commands=result, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                   sanitizer=None, instrumented_coverage=False, linux_asan_status='awaiting-reviewed-CI',
                   qualification=False)
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'summary': str(out / 'summary.json'), 'source_stable': stable, 'commands': result}))
    if not stable or len(result) != len(commands) or any(x['exit_code'] for x in result):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
