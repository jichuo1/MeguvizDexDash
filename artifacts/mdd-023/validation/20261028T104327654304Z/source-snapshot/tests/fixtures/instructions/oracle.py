"""Independent, deliberately scoped Python oracle for the hand code fixtures.

Does not import Rust, generated opcodes or AOSP reader code. It validates the
fixture header identities and hand-selected operand/payload/handler/debug facts,
not the complete DEX or ART type-flow contract. Gates remain active under -O.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys
import zlib

HERE=Path(__file__).resolve().parent


def require(condition,message):
    if not condition:raise ValueError(message)


def u16(data,at):
    require(0<=at<=len(data)-2,'TRUNCATED_U16')
    return struct.unpack_from('<H',data,at)[0]


def u32(data,at):
    require(0<=at<=len(data)-4,'TRUNCATED_U32')
    return struct.unpack_from('<I',data,at)[0]


def leb(data,at,end,signed=False):
    value=0
    for n in range(5):
        require(at<end,'TRUNCATED_LEB')
        byte=data[at];at+=1;value|=(byte&127)<<(7*n)
        if byte<128:
            if signed and byte&64:value-=1<<(7*(n+1))
            require(-(1<<31)<=value<(1<<31) if signed else 0<=value<(1<<32),'LEB_OVERFLOW')
            return value,at
    raise ValueError('LEB_OVERFLOW')


def debug(data,at,end,registers,code_size,strict=False):
    line,at=leb(data,at,end);initial=line;invalid_line=line<1;outside=False
    parameters,at=leb(data,at,end)
    require(parameters<=65536,'DEBUG_PARAMETER_COUNT_EXCEEDS_FORMAT');unnamed=True
    for _ in range(parameters):value,at=leb(data,at,end);unnamed=unnamed and value==0
    pc=0;positions=[];operations=[]
    while True:
        require(at<end,'TRUNCATED_DEBUG')
        op=data[at];at+=1;operations.append(op)
        if op==0:break
        if op==1:
            delta,at=leb(data,at,end);pc+=delta
        elif op==2:
            delta,at=leb(data,at,end,True);line+=delta
        elif op in (3,4,5,6):
            reg,at=leb(data,at,end);require(reg<registers,'DEBUG_REGISTER_RANGE')
            if op in (3,4):
                for _ in range(3 if op==4 else 2):_,at=leb(data,at,end)
        elif op==9:_,at=leb(data,at,end)
        elif op>=10:
            pc+=(op-10)//15;line+=-4+(op-10)%15;positions.append([pc,line])
        require(pc<=0xffffffff,'DEBUG_PC_OVERFLOW');require(-(1<<31)<=line<=0xffffffff,'DEBUG_LINE_OVERFLOW')
        outside=outside or pc>code_size;invalid_line=invalid_line or line<1
    pc_based=initial in (0,1) and unnamed and len(operations)>=2 and operations[0]==14 and operations[-1]==0 and all(op==30 for op in operations[1:-1])
    if strict:
        require(not pc_based,'INCOMPLETE_SOURCE_PC_SURROGATE')
        require(not invalid_line,'INCOMPLETE_SOURCE_LINE');require(not outside,'INCOMPLETE_SOURCE_CONTEXT')
    return {'positions':positions,'operations':operations,'applicable_positions':[p for p in positions if p[0]<code_size],
            'usable_source_positions':[p for p in positions if p[0]<code_size and p[1]>0 and not pc_based],
            'representation':'pc_to_pc_pattern' if pc_based else 'event_program'},at


def parse(data,strict=False):
    require(data[:4]==b'dex\n','MAGIC')
    require(u32(data,32)==len(data),'FILE_SIZE')
    require(data[12:32]==hashlib.sha1(data[32:]).digest(),'SHA1')
    require(u32(data,8)==zlib.adler32(data[12:])&0xffffffff,'ADLER32')
    at=u32(data,52);count=u32(data,at);sections=[]
    for n in range(count):
        kind,unused,total,offset=struct.unpack_from('<HHII',data,at+4+n*12)
        require(unused==0,'MAP_UNUSED');sections.append((offset,kind,total))
    sections.sort();bounds={kind:(offset,sections[n+1][0] if n+1<len(sections) else len(data),total)
                            for n,(offset,kind,total) in enumerate(sections)}
    at,code_end,total=bounds[0x2001];items=[]
    for _ in range(total):
        at=(at+3)&~3;begin=at
        regs,ins,outs,tries,debug_at,size=struct.unpack_from('<HHHHII',data,at)
        require(ins<=regs,'INS_REGISTERS');require(outs<=5 or outs<=regs,'OUTS_REGISTER_LAYOUT')
        at+=16;raw=data[at:at+size*2];require(len(raw)==size*2,'TRUNCATED_CODE');at+=size*2
        words=list(struct.unpack('<'+'H'*size,raw))
        if words and words[0]&255==0x3e:raise ValueError('RESERVED_OPCODE')
        if words and words[0]&255==0x18:require(len(words)>=5,'TRUNCATED_WIDE')
        record={'offset':begin,'registers':regs,'outs':outs,'words':words,'insns_bytes':raw.hex(),'tries':[],'handlers':[]}
        if tries:
            if size%2:require(u16(data,at)==0,'TRY_PADDING');at+=2
            for _ in range(tries):
                start,length,handler=struct.unpack_from('<IHH',data,at);at+=8
                require(length>0 and start+length<=size,'TRY_RANGE');record['tries'].append([start,length,handler])
            origin=at;handlers,at=leb(data,at,code_end)
            for _ in range(handlers):
                relative=at-origin;length,at=leb(data,at,code_end,True);typed=[]
                for _ in range(abs(length)):
                    kind,at=leb(data,at,code_end);target,at=leb(data,at,code_end);typed.append([kind,target])
                catch_all=None
                if length<=0:catch_all,at=leb(data,at,code_end)
                record['handlers'].append({'relative':relative,'typed':typed,'catch_all':catch_all})
        record['code_bytes']=data[begin:at].hex()
        if words and words[0]&255 in (0x26,0x2b,0x2c):
            target=struct.unpack('<i',struct.pack('<HH',words[1],words[2]))[0];tag=words[target]
            if tag==0x100:
                amount=words[target+1];key=struct.unpack('<i',struct.pack('<HH',*words[target+2:target+4]))[0]
                targets=[struct.unpack('<i',struct.pack('<HH',*words[target+4+n*2:target+6+n*2]))[0] for n in range(amount)]
                record['payload']={'kind':'packed','first_key':key,'targets':targets}
            elif tag==0x200:
                amount=words[target+1]
                values=[struct.unpack('<i',struct.pack('<HH',*words[target+2+n*2:target+4+n*2]))[0] for n in range(amount*2)]
                record['payload']={'kind':'sparse','keys':values[:amount],'targets':values[amount:]}
            else:
                require(tag==0x300,'ARRAY_TAG');width=words[target+1];amount=words[target+2]+(words[target+3]<<16)
                body=struct.pack('<'+'H'*(len(words)-target-4),*words[target+4:])[:width*amount]
                record['payload']={'kind':'array','width':width,'count':amount,'bytes':list(body)}
        if debug_at:
            record['debug'],_=debug(data,debug_at,bounds[0x2003][1],regs,size,strict)
        items.append(record)
    return items


def main():
    manifest=json.loads((HERE/'manifest.json').read_text(encoding='utf-8'));results=[]
    for entry in manifest['files']:
        path=HERE/'generated'/entry['path'];data=path.read_bytes()
        require(len(data)==entry['bytes'] and hashlib.sha256(data).hexdigest()==entry['sha256'],'FIXTURE_IDENTITY')
        require(entry['encoded_expectation'] in ('valid','invalid'),'UNKNOWN_EXPECTATION')
        expected_error=entry['encoded_expectation']=='invalid'
        try:
            items=parse(data);require(not expected_error,'EXPECTED_INVALID_INPUT_ACCEPTED')
            name=entry['path']
            if name=='unreferenced-two-code.dex':
                require([x['offset'] for x in items]==[112,132],'CODE_MAP_MULTIPLICITY');require(all(x['words']==[14] for x in items),'RETURN_BYTES')
            elif name=='packed-switch.dex':require(items[0]['payload']=={'kind':'packed','first_key':7,'targets':[3]},'PACKED_GOLDEN')
            elif name=='sparse-switch.dex':require(items[0]['payload']=={'kind':'sparse','keys':[1,3],'targets':[3,3]},'SPARSE_GOLDEN')
            elif name=='fill-array.dex':require(items[0]['payload']=={'kind':'array','width':1,'count':3,'bytes':[1,2,3]},'ARRAY_GOLDEN')
            elif name=='try-catch-all.dex':require(items[0]['handlers']==[{'relative':1,'typed':[],'catch_all':1}],'HANDLER_GOLDEN')
            elif name=='try-end-inside-instruction.dex':require(items[0]['tries']==[[0,1,1]],'TRY_UNIT_GOLDEN')
            elif name=='all-debug-opcodes.dex':require(items[0]['debug']['positions']==[[0,1]],'DEBUG_GOLDEN')
            elif name.startswith('debug-intermediate-state-'):require(items[0]['debug']['positions']==[[3,1]],'DEBUG_STATE_GOLDEN')
            elif name=='debug-code-unit-interior-position.dex':require(items[0]['debug']['positions']==[[1,2]],'DEBUG_CODE_UNIT_GOLDEN')
            elif name=='debug-code-unit-interior-local.dex':require(items[0]['debug']['positions']==[],'DEBUG_LOCAL_GOLDEN')
            elif name.startswith('pc-to-pc-shared-base-'):
                base=int(name[-5]);require(len(items)==2,'PC_SHARED_COUNT')
                require(all(x['debug']['positions']==[[pc,pc+base] for pc in range(6)] for x in items),'PC_SHARED_RAW')
                require(items[0]['debug']['applicable_positions']==[[0,base]],'PC_SHORT_VIEW')
                require(items[1]['debug']['applicable_positions']==[[pc,pc+base] for pc in range(4)],'PC_LONG_VIEW')
            elif name=='debug-line-u32max.dex':require(items[0]['debug']['positions']==[[0,4294967295]],'DEBUG_LINE_WIDTH')
            elif name=='debug-observed-zero-source-line.dex':
                require([18,0] in items[0]['debug']['positions'],'OBSERVED_ZERO_RAW')
                require([18,0] not in items[0]['debug']['usable_source_positions'],'ZERO_NOT_SOURCE_LINE')
                require([34,32] in items[0]['debug']['positions'],'RESTORED_LINE_RAW')
            if entry['strict_source_line_expectation']=='incomplete':
                rejected=False
                try:parse(data,strict=True)
                except ValueError as error:
                    require(str(error).startswith('INCOMPLETE_SOURCE_'),'WRONG_STRICT_FAILURE:'+str(error));rejected=True
                require(rejected,'STRICT_SOURCE_POLICY_ACCEPTED_UNKNOWN')
            results.append({'path':entry['path'],'status':'expected_valid','items':items})
        except ValueError as error:
            require(expected_error,'UNEXPECTED_ORACLE_ERROR:'+str(error))
            require(str(error)!='EXPECTED_INVALID_INPUT_ACCEPTED','BAD_FIXTURE_ACCEPTED')
            results.append({'path':entry['path'],'status':'expected_invalid','error':str(error)})
    output={'schema_version':'mdd.manual-code-oracle.v1','oracle':'independent Python struct/LEB readers plus explicit hand expectations',
            'scope':'the listed synthetic code/payload/catch/debug fixtures only; not a full opcode decoder or complete ART oracle',
            'valid':sum(r['status']=='expected_valid' for r in results),'invalid':sum(r['status']=='expected_invalid' for r in results),'results':results}
    if len(sys.argv)>1:Path(sys.argv[1]).write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'valid':output['valid'],'invalid':output['invalid'],'gates_active_with_optimized_python':True}))


if __name__=='__main__':main()
