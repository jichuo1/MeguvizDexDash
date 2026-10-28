#!/usr/bin/env python3
"""Hand-layout physical item-start fixtures; no production parser imports."""
from pathlib import Path
import hashlib
import struct
import zlib

HERE = Path(__file__).resolve().parent


def finish(data):
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return data


def string_case(offset, count=1):
    data=bytearray(172); data[:8]=b'dex\n035\0'
    struct.pack_into('<20I', data,32,172,112,0x12345678,0,0,120,1,112,0,0,0,0,0,0,0,0,0,0,56,116)
    struct.pack_into('<I',data,112,offset)
    struct.pack_into('<I',data,120,4)
    for ordinal,(kind,size,start) in enumerate([(0,1,0),(1,1,112),(0x2002,count,116),(0x1000,1,120)]):
        struct.pack_into('<HHII',data,124+ordinal*12,kind,0,size,start)
    return finish(data)


def list_case(offset):
    data=bytearray(232); data[:8]=b'dex\n035\0'
    struct.pack_into('<20I',data,32,232,112,0x12345678,0,0,144,1,112,1,116,1,120,0,0,0,0,0,0,100,132)
    struct.pack_into('<I',data,112,132)
    struct.pack_into('<III',data,120,0,0,offset)
    data[132:135]=b'\1V\0'
    struct.pack_into('<IH',data,136,1,0)
    struct.pack_into('<I',data,144,7)
    for ordinal,(kind,start) in enumerate([(0,0),(1,112),(2,116),(3,120),(0x2002,132),(0x1001,136),(0x1000,144)]):
        struct.pack_into('<HHII',data,148+ordinal*12,kind,0,1,start)
    return finish(data)


def main():
    cases={'valid-empty-string.dex':string_case(116),
           'bad-interior-string.dex':string_case(117),
           'valid-orphan-string-data.dex':string_case(116,2),
           'valid-unused-type-list.dex':list_case(0),
           'bad-interior-type-list.dex':list_case(140)}
    for name,data in cases.items():
        (HERE/name).write_bytes(data)
    print('generated 5 independent physical-item-start fixtures')


if __name__=='__main__': main()
