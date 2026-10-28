"""Reproduce instruction vectors and synthetic map-code fixtures; not installable APKs.

Opcode descriptors share AOSP ancestry with the implementation. Explicit hand
expectations are separately listed; this script does not import the Rust parser.
"""
from pathlib import Path
import hashlib
import json
import struct
import zlib

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def code_item(units, registers=16, outs=0, tries=None, debug_offset=0):
    result=bytearray(struct.pack('<HHHHII',registers,0,outs,1 if tries else 0,debug_offset,len(units)))
    result+=struct.pack('<'+'H'*len(units),*units)
    if tries:
        if len(units)%2: result+=b'\0\0'
        result+=struct.pack('<IHH',0,1,1)+bytes(tries)
    return result


def dex(items, debug=b'', version='040'):
    body=bytearray(); offsets=[]
    for item in items:
        while (112+len(body))%4:body+=b'\0'
        offsets.append(112+len(body));body+=item
    debug_offset=112+len(body)
    if debug:body+=debug
    while (112+len(body))%4:body+=b'\0'
    map_at=112+len(body)
    entries=[(0,1,0),(0x2001,len(items),112)]
    if debug:entries.append((0x2003,1,debug_offset))
    entries.append((0x1000,1,map_at))
    body+=struct.pack('<I',len(entries))
    for kind,count,offset in entries:body+=struct.pack('<HHII',kind,0,count,offset)
    result=bytearray(112)+body
    result[:8]=b'dex\n'+version.encode()+b'\0'
    struct.pack_into('<III',result,32,len(result),112,0x12345678)
    struct.pack_into('<I',result,52,map_at)
    struct.pack_into('<II',result,104,len(result)-112,112)
    result[12:32]=hashlib.sha1(result[32:]).digest()
    struct.pack_into('<I',result,8,zlib.adler32(result[12:])&0xffffffff)
    return bytes(result),offsets,debug_offset


def main():
    output=HERE/'generated';output.mkdir(exist_ok=True)
    matrix=json.loads((ROOT/'conformance/dex/instruction-matrix.json').read_text(encoding='utf-8'))
    vectors=[]
    widths={**{x:1 for x in ['10x','12x','11n','11x','10t']},
            **{x:2 for x in ['20t','22x','21t','21s','21h','21c','23x','22b','22t','22s','22c']},
            **{x:3 for x in ['32x','30t','31t','31i','31c','35c','3rc']},'45cc':4,'4rcc':4,'51l':5}
    for item in matrix['entries']:
        if item['reserved']:continue
        op=item['opcode'];fmt=item['format'];words=[op]+[0]*(widths[fmt]-1)
        if fmt=='10t':words[0]|=widths[fmt]<<8
        if fmt in ['20t','21t','22t','30t']:words[1]=widths[fmt]
        if fmt in ['35c','45cc']:words[0]|=0x1000
        if fmt in ['3rc','4rcc']:words[0]|=0x0100
        if fmt=='31t':
            words[1]=4
            words+=[0x000e]
            if op==0x26:words+=[0x0300,1,1,0,0]
            if op==0x2b:words+=[0x0100,1,0,0,3,0]
            if op==0x2c:words+=[0x0200,1,0,0,3,0]
        else:words+=[0x000e]
        vectors.append({'opcode':op,'format':fmt,'mnemonic':item['mnemonic'],'words':words,'expected_first_width':widths[fmt]})
    (output/'all-opcodes.json').write_text(json.dumps({'kind':'AOSP-ancestry-derived-format-vectors','vectors':vectors},indent=2)+'\n',encoding='utf-8',newline='\n')
    manual=[
        {'id':'12x-register-order','words':[0x2101,0x000e],'registers':[1,2],'format':'12x'},
        {'id':'11n-negative-literal','words':[0xf112,0x000e],'registers':[1],'literal':'-1'},
        {'id':'22x-full-register-width','words':[0x0202,0x0123,0x000e],'registers':[2,291]},
        {'id':'35c-register-order','words':[0x556e,3,0x4321,0x000e],'registers':[1,2,3,4,5],'method_idx':3},
        {'id':'3rc-range','words':[0x0374,3,16,0x000e],'registers':[16,17,18],'method_idx':3},
        {'id':'45cc-two-references','words':[0x20fa,3,0x0032,4,0x000e],'registers':[2,3],'method_idx':3,'prototype_idx':4},
        {'id':'4rcc-two-references','words':[0x03fb,3,16,4,0x000e],'registers':[16,17,18],'method_idx':3,'prototype_idx':4},
        {'id':'custom-not-ordinary','words':[0x10fc,3,0,0x000e],'registers':[0],'call_site_idx':3},
        {'id':'51l-lossless-bits','words':[0x0218,0x7788,0x5566,0x3344,0x1122,0x000e],'registers':[2],'literal':str(0x1122334455667788)},
    ]
    (output/'manual-expectations.json').write_text(json.dumps({'kind':'hand-specified-operand-expectations','vectors':manual},indent=2)+'\n',encoding='utf-8',newline='\n')
    records=[]
    def save(name,items,debug=b'',version='040'):
        data,offsets,debug_at=dex(items,debug,version);(output/name).write_bytes(data)
        semantic_unknown=name in {'bad-debug-initial-zero.dex','bad-debug-advance-zero.dex',
            'bad-debug-special-negative.dex','bad-debug-nonpattern-shared-suffix.dex','debug-observed-zero-source-line.dex'}
        records.append({'path':name,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'code_offsets':offsets,'debug_offset':debug_at if debug else None,'kind':'synthetic-layout-fixture-not-installable-APK',
                        'encoded_expectation':'valid' if semantic_unknown or not name.startswith('bad-') else 'invalid',
                        'strict_source_line_expectation':'incomplete' if semantic_unknown or name.startswith('pc-to-pc-shared-') else 'not_requested'})
    # No method refers to either code_item: full map enumeration must retain both.
    first=code_item([0x000e],registers=0,outs=0);second=code_item([0x000e],registers=0,outs=0)
    _,_,debug_at=dex([first,second],b'\x01\x00\x00')
    second=code_item([0x000e],registers=0,outs=0,debug_offset=debug_at)
    save('unreferenced-two-code.dex',[first,second],b'\x01\x00\x00')
    save('packed-switch.dex',[code_item([0x002b,4,0,0x000e,0x0100,1,7,0,3,0],registers=1)])
    save('sparse-switch.dex',[code_item([0x002c,4,0,0x000e,0x0200,2,1,0,3,0,3,0,3,0],registers=1)])
    save('fill-array.dex',[code_item([0x0026,4,0,0x000e,0x0300,1,3,0,0x0201,3],registers=1)])
    save('try-catch-all.dex',[code_item([0x0027,0x000d,0x000e],registers=1,tries=[1,0,1])])
    debug=bytes([2,0,1,0,2,0x7f,3,0,0,0,4,0,0,0,0,5,0,6,0,7,8,9,0,0x0e,0])
    body=code_item([0x000e],registers=1);_,_,debug_at=dex([body],debug)
    save('all-debug-opcodes.dex',[code_item([0x000e],registers=1,debug_offset=debug_at)],debug)
    # Valid checksum/signature negative fixtures reach code decoding, not header rejection.
    save('bad-reserved-opcode.dex',[code_item([0x003e],registers=1)])
    save('bad-truncated-wide.dex',[code_item([0x0018,0],registers=2)])
    for state_opcode in [7,8,9]:
        debug=bytes([1,0,1,1,state_opcode]+([0] if state_opcode==9 else [])+[1,2,0x0e,0])
        body=code_item([0x0014,0,0,0x000e],registers=1);_,_,debug_at=dex([body],debug)
        save('debug-intermediate-state-'+str(state_opcode)+'.dex',
             [code_item([0x0014,0,0,0x000e],registers=1,debug_offset=debug_at)],debug)
    save('try-end-inside-instruction.dex',[code_item([0x0014,0,0,0x000e],registers=1,tries=[1,0,3])])
    for name,debug in [('position',bytes([1,0,0x1e,0])),
                       ('local',bytes([1,0,1,1,3,0,0,0,5,0,6,0,0]))]:
        body=code_item([0x0014,0,0,0x000e],registers=1);_,_,debug_at=dex([body],debug)
        save('debug-code-unit-interior-'+name+'.dex',
             [code_item([0x0014,0,0,0x000e],registers=1,debug_offset=debug_at)],debug)
    for base_line in [0,1]:
        debug=bytes([base_line,0,0x0e]+[0x1e]*5+[0])
        bodies=[code_item([0x000e],registers=0),code_item([0x0014,0,0,0x000e],registers=1)]
        _,_,debug_at=dex(bodies,debug)
        save('pc-to-pc-shared-base-'+str(base_line)+'.dex',
             [code_item([0x000e],registers=0,debug_offset=debug_at),
              code_item([0x0014,0,0,0x000e],registers=1,debug_offset=debug_at)],debug)
    for name,debug in [('initial-zero',bytes([0,0,0])),('advance-zero',bytes([1,0,2,0x7f,0])),
                       ('special-negative',bytes([1,0,0x0a,0])),('missing-end',bytes([1,0,1,0,1,0])),
                       ('parameter-count',bytes([1,0x81,0x80,0x04,0]))]:
        body=code_item([0x000e],registers=1);_,_,debug_at=dex([body],debug)
        save('bad-debug-'+name+'.dex',[code_item([0x000e],registers=1,debug_offset=debug_at)],debug)
    for name,debug in [('debug-line-u32max',bytes([255,255,255,255,15,0,0x0e,0])),
                       ('bad-debug-line-overflow',bytes([255,255,255,255,15,0,2,1,0])),
                       ('bad-debug-nonpattern-shared-suffix',bytes([1,0,0x0e,1,3,0]))]:
        body=code_item([0x000e],registers=1);_,_,debug_at=dex([body],debug)
        save(name+'.dex',[code_item([0x000e],registers=1,debug_offset=debug_at)],debug)
    # Public NewPipe event sequence reduced to an independently generated code
    # body; line30 -> 0 is emitted at PC18, then line advances back to32.
    debug=bytes.fromhex('1a000e4c4b4b0262680220fe020b4a4b01101002672c2d2d00')
    units=[0]*71+[0x000e];body=code_item(units,registers=2);_,_,debug_at=dex([body],debug)
    save('debug-observed-zero-source-line.dex',[code_item(units,registers=2,debug_offset=debug_at)],debug)
    manifest={'schema_version':'mdd.instruction-fixtures.v1','generator':'tests/fixtures/instructions/generate.py',
              'opcode_vector_count':len(vectors),'format_count':len({v['format'] for v in vectors}),
              'manual_expectation_count':len(manual),'files':records,'oracle_note':'AOSP-derived full-coverage vectors are not independent of opcode metadata; literal expectations and explicit malformed cases supplement them.'}
    (HERE/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'opcode_vectors':len(vectors),'formats':manifest['format_count'],'full_dex_fixtures':len(records)}))


if __name__=='__main__':main()
