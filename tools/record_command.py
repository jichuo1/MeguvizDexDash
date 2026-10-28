#!/usr/bin/env python3
"""Record actual command results; this is not a benchmark harness."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


def run() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cwd', type=Path, default=Path.cwd())
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('command is required')
    args.output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    before = time.monotonic()
    result = subprocess.run(command, cwd=args.cwd, capture_output=True, check=False)
    record = {
        'schema_version': 'mdd.command-record.v1',
        'command': command, 'cwd': str(args.cwd.resolve()),
        'started_utc': started,
        'finished_utc': datetime.now(timezone.utc).isoformat(),
        'elapsed_seconds': time.monotonic() - before,
        'exit_code': result.returncode,
        'measurement_scope': 'development validation, not performance qualification',
    }
    for name, data in [('stdout', result.stdout), ('stderr', result.stderr)]:
        (args.output / (name + '.txt')).write_bytes(data)
        record[name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    (args.output / 'record.json').write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(run())
