#!/usr/bin/env python3
"""Scalar handwritten fixture oracle. Handles only the declared tiny opcode set."""
from __future__ import annotations
import hashlib,json,struct,zlib
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
A="Lfixture/A;"
def require(condition,message):
    if not condition:raise ValueError(message)
def type_name(value):
    dimensions=len(value)-len(value.lstrip("["));rest=value[dimensions:]
    name={"I":"int","V":"void","J":"long","D":"double"}.get(rest,rest[1:-1].replace("/",".") if rest.startswith("L") else rest)
    return name+"[]"*dimensions

class Oracle:
    def __init__(self,data):
        self.data=data;require(len(data)>=112,"header")
        require(hashlib.sha1(data[32:]).digest()==data[12:32],"SHA1")
        require(zlib.adler32(data[12:])&0xffffffff==struct.unpack_from("<I",data,8)[0],"Adler32")
        self.header=struct.unpack_from("<20I",data,32);require(self.header[0]==len(data),"size")
        self.map={kind:(count,offset) for kind,unused,count,offset in [self.unpack("<HHII",self.header[5]+4+i*12) for i in range(self.u32(self.header[5]))]}
        self.strings=[];self.units=[];self.raw_strings=[]
        for i in range(self.header[6]):
            at=self.u32(self.header[7]+4*i);length,at=self.uleb(at);end=data.find(b"\0",at);require(end>=0,"string terminator")
            raw=data[at:end];text=raw.replace(b"\xc0\x80",b"\0").decode("utf8","surrogatepass");u16=text.encode("utf-16-le","surrogatepass")
            units=list(struct.unpack("<"+"H"*(len(u16)//2),u16));require(len(units)==length,"utf16 length")
            self.strings.append(text);self.units.append(units);self.raw_strings.append(raw.hex())
        self.types=[self.strings[self.u32(self.header[9]+4*i)] for i in range(self.header[8])]
        self.protos=[]
        for i in range(self.header[10]):
            shorty,ret,at=self.unpack("<III",self.header[11]+12*i);args=[] if not at else list(self.unpack("<"+"H"*self.u32(at),at+4));self.protos.append((self.types[ret],[self.types[index] for index in args]))
        self.fields=[]
        for i in range(self.header[12]):
            owner,ty,name=self.unpack("<HHI",self.header[13]+8*i);self.fields.append((self.types[owner],self.strings[name],self.types[ty]))
        self.methods=[]
        for i in range(self.header[14]):
            owner,proto,name=self.unpack("<HHI",self.header[15]+8*i);ret,args=self.protos[proto];self.methods.append((self.types[owner],self.strings[name],ret,args,proto,owner))
        self.code={}
        if 0x2001 in self.map:
            count,at=self.map[0x2001]
            for _ in range(count):
                at=(at+3)&~3;start=at;registers,ins,outs,tries,debug,n=self.unpack("<HHHHII",at);require(tries==0 and debug==0,"fixture subset")
                words=list(self.unpack("<"+"H"*n,at+16));self.code[start]={"offset":start,"registers":registers,"ins":ins,"outs":outs,"words":words,"instructions":self.instructions(words,start+16)};at+=16+n*2
        self.definitions=[]
        for class_def in range(self.header[16]):
            owner,flags,parent,interfaces,source,annotations,at,static=self.unpack("<8I",self.header[17]+class_def*32)
            if not at:continue
            counts=[]
            for _ in range(4):value,at=self.uleb(at);counts.append(value)
            for count in counts[:2]:
                field=0
                for _ in range(count):delta,at=self.uleb(at);flag,at=self.uleb(at);field+=delta;require(field<len(self.fields),"field idx")
            for count in counts[2:]:
                method=0
                for _ in range(count):delta,at=self.uleb(at);flag,at=self.uleb(at);code,at=self.uleb(at);method+=delta;require(method<len(self.methods),"method idx");self.definitions.append((method,owner,flag,code,class_def))
    def unpack(self,fmt,at):require(0<=at and at+struct.calcsize(fmt)<=len(self.data),"bounds");return struct.unpack_from(fmt,self.data,at)
    def u32(self,at):return self.unpack("<I",at)[0]
    def uleb(self,at):
        value=0
        for i in range(5):
            require(at+i<len(self.data),"leb truncated");byte=self.data[at+i];value+=(byte&127)*128**i
            if byte<128:require(value<=0xffffffff,"leb overflow");return value,at+i+1
        raise ValueError("leb overflow")
    def method_descriptor(self,index):owner,name,ret,args,_,_=self.methods[index];return owner+"->"+name+"("+"".join(args)+")"+ret
    def instructions(self,words,base):
        result=[];pc=0
        while pc<len(words):
            word=words[pc];op=word&255
            if op==14:pc+=1;continue
            width={0x1a:2,0x1b:3,0x1c:2,0x62:2,0x69:2,0x71:3,0x77:3,0xfa:4,0xfb:4,0xfc:3,0xfd:3,0xfe:2,0xff:2}.get(op)
            require(width is not None and pc+width<=len(words),"fixture opcode/width")
            kind={0x1a:"string",0x1b:"string",0x1c:"type",0x62:"field",0x69:"field",0x71:"method",0x77:"method",0xfa:"method",0xfb:"method",0xfc:"call_site",0xfd:"call_site",0xfe:"method_handle",0xff:"prototype"}[op]
            index=words[pc+1]+((words[pc+2]<<16) if op==0x1b else 0)
            limits={"string":len(self.strings),"type":len(self.types),"field":len(self.fields),"method":len(self.methods),"prototype":len(self.protos),"call_site":self.map.get(7,(0,0))[0],"method_handle":self.map.get(8,(0,0))[0]}
            require(index<limits[kind],"invalid_code_operand")
            refs=[(kind,index,base+pc*2+2,4 if op==0x1b else 2)]
            if op in [0xfa,0xfb]:require(words[pc+3]<len(self.protos),"poly_proto_index");refs.append(("prototype",words[pc+3],base+pc*2+6,2))
            count=(word>>8) if op in [0x77,0xfb,0xfd] else (word>>12) if op in [0x71,0xfa,0xfc] else None
            result.append({"pc":pc,"opcode":op,"width":width,"refs":refs,"args":count});pc+=width
        return result
    def call_site(self,index):
        count,table=self.map[7];require(index<count,"callsite index");offset=self.u32(table+4*index);start_count,start=self.map[0x2005];starts={}
        for _ in range(start_count):
            at=start;n,at=self.uleb(at);children=[]
            for _ in range(n):
                tag=self.data[at];require(tag in [0x15,0x16,0x17],"custom_prefix");children.append((tag,self.data[at+1]));at+=2
            starts[start]=children;start=at
        require(offset in starts,"custom array item start");children=starts[offset];require(len(children)>=3 and [v[0] for v in children[:3]]==[0x16,0x17,0x15],"custom_prefix")
        require(children[0][1]<self.map.get(8,(0,0))[0] and children[1][1]<len(self.strings) and children[2][1]<len(self.protos),"custom metadata index")
        return children[2][1]
    def read(self):
        rows={name:[] for name in ["method_strings","method_calls","method_field_accesses","method_used_types"]};sites=[];dynamic=[];unowned=set(self.code);no_body=[];scalar=True
        for method,class_idx,flags,offset,class_def_idx in self.definitions:
            if not offset: no_body.append(method);continue
            require(offset in self.code,"body_not_physical_start");item=self.code[offset];unowned.discard(offset)
            owner,name,ret,args,proto,_=self.methods[method];words=sum(2 if value in ["J","D"] else 1 for value in args)+(0 if flags&8 else 1);require(words==item["ins"],"caller_ins_words")
            caller=self.method_descriptor(method)
            for instruction in item["instructions"]:
                op=instruction["opcode"];kind,index,*_=instruction["refs"][0]
                if instruction["args"] is not None:
                    if op in [0xfc,0xfd]:prototype=self.call_site(index);extra=0
                    elif op in [0xfa,0xfb]:prototype=instruction["refs"][1][1];extra=1
                    else:prototype=self.methods[index][4];extra=0
                    wanted=extra+sum(2 if value in ["J","D"] else 1 for value in self.protos[prototype][1]);require(instruction["args"]==wanted,"custom_argument_words" if op in [0xfc,0xfd] else "invoke_argument_words")
                for operand_ordinal,(reference,target,at,length) in enumerate(instruction["refs"]):
                    sites.append({"caller_method_idx":method,"class_def_idx":class_def_idx,"class_idx":class_idx,"pc":instruction["pc"],"operand_ordinal":operand_ordinal,"kind":reference,"index":target,"byte_offset":at,"byte_length":length,"opcode":op})
                    common={"method":caller,"method_class":owner,"method_name":name,"file_id":0,"class_idx":class_idx,"method_idx":method}
                    if reference=="string":
                        units=self.units[target]
                        try:value=struct.pack("<"+"H"*len(units),*units).decode("utf-16-le","strict")
                        except UnicodeDecodeError:
                            scalar=False;value={"encoding":"dex_utf16","units":units,"raw_mutf8_hex":self.raw_strings[target]}
                        rows["method_strings"].append({**common,"value":value,"string_idx":target})
                    elif reference=="method":
                        callee=self.methods[target];rows["method_calls"].append({**common,"callee":self.method_descriptor(target),"callee_class":callee[0],"callee_name":callee[1],"callee_method_idx":target})
                    elif reference=="field":
                        field=self.fields[target];rows["method_field_accesses"].append({**common,"field":field[0]+"->"+field[1]+":"+field[2],"field_class":field[0],"field_name":field[1],"field_type":field[2],"using_type":"get" if op==0x62 else "put","field_idx":target})
                    elif reference=="type":rows["method_used_types"].append({**common,"type_descriptor":self.types[target],"type_name":type_name(self.types[target]),"type_idx":target})
                    elif reference=="call_site":dynamic.append({"caller_method_idx":method,"pc":instruction["pc"],"call_site_idx":target,"runtime_target":"unknown_dynamic_target"})
        return {"relations":rows,"sites":sites,"dynamic_calls":dynamic,"no_body_method_indices":no_body,"unowned_code_offsets":sorted(unowned),"plain_scalar_string_projection":scalar,"raw_string_values":[{"string_idx":i,"utf16_units":units,"mutf8_hex":self.raw_strings[i]} for i,units in enumerate(self.units) if any(0xd800<=u<=0xdfff for u in units)]}

def main():
    manifest=json.loads((HERE/"manifest.json").read_text());expected=json.loads((HERE/"expected.json").read_text());results=[]
    for item in manifest["files"]:
        path=ROOT/item["path"];data=path.read_bytes();require(hashlib.sha256(data).hexdigest()==item["sha256"],"identity")
        try:
            oracle=Oracle(data);out=oracle.read();require(item["reference_build_expected"]=="complete","unexpected acceptance")
            case=path.stem
            if case=="classic-035":
                for kind,key in [("string","string_pcs"),("type","type_pcs"),("field","field_pcs"),("method","method_pcs")]:require([s["pc"] for s in out["sites"] if s["kind"]==kind]==expected["classic"][key],"manual PCs")
            if case in ["classic-035","orphan-code-035","defined-field-035","ordinary-unrelated-bad-annotation"]:require({name:len(rows) for name,rows in out["relations"].items()}==expected["classic"]["relation_counts"],"manual classic counts")
            if case=="shared-code-035":require(len(out["sites"])==expected["shared_code"]["site_count"],"manual shared multiplicity")
            if case=="poly-custom-038":require(len(out["sites"])==expected["poly_custom"]["site_count"] and [value["pc"] for value in out["dynamic_calls"]]==expected["poly_custom"]["custom_call_pcs"],"manual custom sites")
            if case=="handles-039":require(len(out["sites"])==expected["handles"]["site_count"] and len(out["relations"]["method_calls"])==4,"handle constant is not invocation")
            results.append({"path":item["path"],"sha256":item["sha256"],"status":"complete",**out})
        except ValueError as error:
            require(item["reference_build_expected"]=="invalid","oracle rejected valid fixture: "+str(error));results.append({"path":item["path"],"sha256":item["sha256"],"status":"invalid","reason":str(error)})
    report={"schema_version":"mdd.reference-independent-oracle.v1","results":results,"success":True,"scope":"Handwritten tiny-opcode scalar oracle over source bytes; no Rust parser or writer imports, no runtime dispatch/ART type-flow proof"}
    (HERE/"oracle-results.json").write_text(json.dumps(report,indent=2,ensure_ascii=True,allow_nan=False)+"\n",encoding="utf8")
    print("independent reference oracle passed:",len(results),"fixtures;",sum(r["status"]=="complete" for r in results),"complete; rest explicitly invalid")
if __name__=="__main__":main()
