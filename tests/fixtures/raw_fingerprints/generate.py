#!/usr/bin/env python3
"""Generate one same-length invalid method-code reference; do not rewrite expectations."""
from pathlib import Path
import hashlib
import struct
import zlib

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]


def main():
    data=bytearray((ROOT/'tests/fixtures/generated/structured-035.dex').read_bytes())
    class_table=struct.unpack_from('<I',data,100)[0]
    cursor=struct.unpack_from('<I',data,class_table+24)[0]
    def leb(at):
        value=shift=0
        while True:
            byte=data[at];at+=1;value|=(byte&127)<<shift
            if byte<128:return value,at
            shift+=7
    counts=[]
    for _ in range(4):value,cursor=leb(cursor);counts.append(value)
    for _ in range(counts[0]+counts[1]):_,cursor=leb(cursor);_,cursor=leb(cursor)
    _,cursor=leb(cursor);_,cursor=leb(cursor);start=cursor;value,end=leb(cursor)
    if value!=304 or end-start!=2:raise ValueError('independent baseline layout changed')
    data[start:end]=bytes([0xb4,2]);data[12:32]=hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff)
    output=HERE/'bad-code-item-reference.dex';output.write_bytes(data)
    print(output.name,hashlib.sha256(data).hexdigest())


if __name__=='__main__':main()
