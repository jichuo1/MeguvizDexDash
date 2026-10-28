#!/usr/bin/env python3
"""Child-only cargo shim: cargo-fuzz 0.13.2 does not forward a --locked flag."""
import json
import os
from pathlib import Path
import sys


def locked_args(args):
    commands = {'build', 'check', 'fetch', 'metadata', 'run', 'test'}
    if not args:
        raise RuntimeError('unexpected empty child cargo invocation')
    separator = args.index('--') if '--' in args else len(args)
    cargo_args, program_args = args[:separator], args[separator:]
    if args[0] in commands and '--locked' not in cargo_args and '--frozen' not in cargo_args:
        return cargo_args + ['--locked'] + program_args
    if args[0] in commands or args == ['--version'] or args == ['-V']:
        return args
    raise RuntimeError(f'unexpected child cargo subcommand: {args[0]}')


if __name__ == '__main__':
    args = locked_args(sys.argv[1:])
    # Preserve the cargo proxy basename: resolving its symlink to rustup changes dispatch.
    executable = Path(os.path.abspath(os.environ['MDD_REAL_CARGO']))
    if not executable.is_file() or executable == Path(__file__).absolute():
        raise RuntimeError('recursive cargo shim')
    with Path(os.environ['MDD_CARGO_LOG']).open('a', encoding='utf-8') as log:
        log.write(json.dumps({'real_cargo': str(executable), 'args': args}) + '\n')
    os.execv(str(executable), [str(executable)] + args)
