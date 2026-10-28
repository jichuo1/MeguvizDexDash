#!/usr/bin/env python3
"""Validate actual CLI JSON against the independent published JSON Schema."""
import argparse
import json
from pathlib import Path
import subprocess
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    process = subprocess.run([str(args.binary.resolve()),'capabilities'], capture_output=True, check=True)
    result = json.loads(process.stdout)
    Draft202012Validator(json.loads((ROOT/'contracts/capabilities.schema.json').read_text(encoding='utf-8'))).validate(result)
    require(not any(p['admitted'] for p in result['profiles']), 'development profile prematurely admitted')
    require(not process.stderr, 'capabilities wrote unexpected stderr')
    invalid = subprocess.run([str(args.binary.resolve()),'unknown-command'], capture_output=True, check=False)
    require(invalid.returncode != 0 and not invalid.stdout, 'invalid command did not fail with clean stdout')
    require(json.loads(invalid.stderr)['code'] == 'INVALID_ARGUMENT', 'invalid command error code mismatch')
    print('Actual capabilities schema, no premature admission, and invalid-command separation passed')


if __name__ == '__main__':
    main()
