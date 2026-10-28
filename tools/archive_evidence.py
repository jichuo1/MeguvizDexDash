#!/usr/bin/env python3
"""Retain oversized evidence bytes losslessly without deleting the local original."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parents[1]


def stream_identity(stream):
    digest, length = hashlib.sha256(), 0
    while block := stream.read(1024 * 1024):
        digest.update(block)
        length += len(block)
    return dict(bytes=length, sha256=digest.hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    if not source.is_relative_to(ROOT / 'artifacts') or not source.is_file():
        raise ValueError('expected an existing evidence file inside project artifacts')
    archive = source.with_name(source.name + '.gz')
    record = source.with_name(source.name + '.archive.json')
    if archive.exists() or record.exists():
        raise ValueError('archive outputs already exist; preserve rather than overwrite them')
    with source.open('rb') as stream:
        original = stream_identity(stream)
    with source.open('rb') as src, archive.open('xb') as dst:
        with gzip.GzipFile(filename='', fileobj=dst, mode='wb', mtime=0) as zipped:
            shutil.copyfileobj(src, zipped, length=1024 * 1024)
    with gzip.open(archive, 'rb') as stream:
        if stream_identity(stream) != original:
            raise ValueError('archive decompression differs from original bytes')
    with source.open('rb') as stream:
        if stream_identity(stream) != original:
            raise ValueError('source changed while archiving')
    with archive.open('rb') as stream:
        compressed = stream_identity(stream)
    result = dict(schema_version='mdd.evidence-archive.v1', compression='gzip; mtime=0; empty filename',
                  original=dict(path=source.relative_to(ROOT).as_posix(), **original),
                  archive=dict(path=archive.relative_to(ROOT).as_posix(), **compressed),
                  lossless_verified=True, local_original_preserved=True,
                  reason='GitHub 100 MiB single-object limit; original raw observation remains unchanged')
    record.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
