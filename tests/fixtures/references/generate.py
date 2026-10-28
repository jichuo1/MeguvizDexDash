#!/usr/bin/env python3
"""Independent reference-site DEX writer; no production parser imports."""
from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path

HERE=Path(__file__).resolve().parent
OUT=HERE/"generated"
A="Lfixture/A;";E="Lfixture/External;";O="Ljava/lang/Object;";S="Ljava/lang/String;";V="V"
MH="Ljava/lang/invoke/MethodHandle;";BSM="Lfixture/Bootstrap;";LOOKUP="Ljava/lang/invoke/MethodHandles$Lookup;";MT="Ljava/lang/invoke/MethodType;";CS="Ljava/lang/invoke/CallSite;"


def require(condition,message):
    if not condition:
        raise ValueError(message)


def leb(value):
    data=bytearray()
    while True:
        byte=value&127;value>>=7;data.append(byte|(128 if value else 0))
        if not value:
            return bytes(data)


def mutf(text):
    units=list(struct.unpack("<"+"H"*(len(text.encode("utf-16-le","surrogatepass"))//2),text.encode("utf-16-le","surrogatepass")))
    data=bytearray(leb(len(units)))
    for unit in units:
        if 0<unit<128:data.append(unit)
        elif unit<2048:data.extend([0xc0|(unit>>6),0x80|(unit&63)])
        else:data.extend([0xe0|(unit>>12),0x80|((unit>>6)&63),0x80|(unit&63)])
    return bytes(data)+b"\0"


def finish(data,version):
    data[:8]=b"dex\n"+version.encode()+b"\0"
    data[12:32]=hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I",data,8,zlib.adler32(data[12:])&0xffffffff)
    return bytes(data)

def lossless_json(value):
    if isinstance(value,str):
        try:value.encode("utf8","strict");return value
        except UnicodeEncodeError:
            raw=value.encode("utf-16-le","surrogatepass")
            try:return raw.decode("utf-16-le","strict")
            except UnicodeDecodeError:return {"encoding":"utf16_units","units":list(struct.unpack("<"+"H"*(len(raw)//2),raw))}
    if isinstance(value,list):return [lossless_json(item) for item in value]
    if isinstance(value,tuple):return [lossless_json(item) for item in value]
    if isinstance(value,dict):
        result={}
        for key,item in value.items():
            encoded=lossless_json(key)
            if not isinstance(encoded,str):encoded="utf16-units:"+".".join(f"{unit:04x}" for unit in encoded["units"])
            result[encoded]=lossless_json(item)
        return result
    return value


def build(case):
    poly=case.startswith("poly-custom")
    handles=case.startswith("handles")
    shared=case=="shared-code-035"
    orphan=case=="orphan-code-035"
    nonscalar=case=="nonscalar-string-035"
    bad_annotation=case in ["ordinary-unrelated-bad-annotation","poly-custom-unrelated-bad-annotation"]
    local_field=case=="defined-field-035"
    extra_types=case=="type-names-035"
    jumbo=case=="jumbo-string-035"
    version="038" if poly else "039" if handles else "035"
    methods=[(A,"caller",V,()),(A,"nativeNoBody",V,()),(A,"target",V,()),(E,"external",V,())]
    if shared:methods.append((A,"aliasCaller",V,()))
    if poly:methods.extend([(MH,"invokeExact",O,("[Ljava/lang/Object;",)),(BSM,"bootstrap",CS,(LOOKUP,S,MT))])
    fields=[(E,"shared",S)]
    if local_field:fields.append((A,"localValue",S))
    if poly:fields.append((E,"handle",MH))
    descriptors={A,E,O,S,V,"I"}|{owner for owner,_,_,_ in methods}|{ret for _,_,ret,_ in methods}|{arg for _,_,_,args in methods for arg in args}|{ty for _,_,ty in fields}
    if bad_annotation:descriptors.add("Lfixture/BadAnnotation;")
    if extra_types:descriptors.add("[I")
    shorty=lambda ret,args:("L" if ret.startswith(("L","[")) else ret)+"".join("L" if arg.startswith(("L","[")) else arg for arg in args)
    texts=set(descriptors)|{name for _,name,_,_ in methods}|{name for _,name,_ in fields}|{shorty(ret,args) for _,_,ret,args in methods}|{"repeat","dynamicVoid"}
    if nonscalar:texts.add("\ud800")
    text=sorted(texts,key=lambda value:list(struct.unpack("<"+"H"*(len(value.encode("utf-16-le","surrogatepass"))//2),value.encode("utf-16-le","surrogatepass"))))
    sx={value:index for index,value in enumerate(text)}
    types=sorted(descriptors,key=sx.__getitem__);tx={value:index for index,value in enumerate(types)}
    protos=sorted({(ret,args) for _,_,ret,args in methods},key=lambda item:(tx[item[0]],tuple(tx[value] for value in item[1])))
    px={value:index for index,value in enumerate(protos)}
    fields=sorted(fields,key=lambda value:(tx[value[0]],sx[value[1]],tx[value[2]]));fx={value:index for index,value in enumerate(fields)}
    methods=sorted(methods,key=lambda value:(tx[value[0]],sx[value[1]],px[(value[2],value[3])]))
    mx={value:index for index,value in enumerate(methods)}
    index_method=lambda owner,name:next(index for index,value in enumerate(methods) if value[0]==owner and value[1]==name)
    string_off=112;type_off=string_off+len(text)*4;proto_off=type_off+len(types)*4
    field_off=proto_off+len(protos)*12;method_off=field_off+len(fields)*8;class_off=method_off+len(methods)*8;data_off=class_off+32
    data=bytearray(data_off)
    entries=[(0,1,0),(1,len(text),string_off),(2,len(types),type_off),(3,len(protos),proto_off),(4,len(fields),field_off),(5,len(methods),method_off),(6,1,class_off)]
    labels={};spans=[]
    def align():data.extend(b"\0"*(-len(data)%4))
    if poly:
        labels["call_site_ids"]=len(data);entries.append((7,1,len(data)));data.extend(b"\0"*4)
    if poly or handles:
        labels["method_handles"]=len(data);entries.append((8,2 if handles else 1,len(data)))
        data.extend(struct.pack("<4H",4,0,index_method(BSM,"bootstrap") if poly else index_method(E,"external"),0))
        if handles:data.extend(struct.pack("<4H",0,0,fx[(E,"shared",S)],0))
    entries.append((0x2002,len(text),len(data)))
    for index,value in enumerate(text):struct.pack_into("<I",data,string_off+4*index,len(data));data.extend(mutf(value))
    for index,value in enumerate(types):struct.pack_into("<I",data,type_off+4*index,sx[value])
    nonempty=[(ret,args) for ret,args in protos if args]
    parameter_offsets={}
    if nonempty:
        align();entries.append((0x1001,len(nonempty),len(data)))
        for ret,args in nonempty:
            align();parameter_offsets[(ret,args)]=len(data);data.extend(struct.pack("<I"+"H"*len(args),len(args),*(tx[value] for value in args)))
    for index,(ret,args) in enumerate(protos):struct.pack_into("<III",data,proto_off+index*12,sx[shorty(ret,args)],tx[ret],parameter_offsets.get((ret,args),0))
    for index,(owner,name,ty) in enumerate(fields):struct.pack_into("<HHI",data,field_off+index*8,tx[owner],tx[ty],sx[name])
    for index,(owner,name,ret,args) in enumerate(methods):struct.pack_into("<HHI",data,method_off+index*8,tx[owner],px[(ret,args)],sx[name])
    if poly:
        labels["call_array"]=len(data);entries.append((0x2005,1,len(data)))
        data.extend(bytes([3,0x16,0,0x17,sx["dynamicVoid"],0x15,px[(V,())]]))
        struct.pack_into("<I",data,labels["call_site_ids"],labels["call_array"])
    units=[];site_expectations=[]
    def emit(words,label=None,target=None):
        pc=len(units);units.extend(words)
        if label:site_expectations.append({"pc":pc,"label":label,"target":target,"words":words})
    literal="\ud800" if nonscalar else "repeat"
    emit([0x001b,sx[literal],0] if jumbo else [0x001a,sx[literal]],"string",literal);emit([0x001b,sx[literal],0] if jumbo else [0x001a,sx[literal]],"string",literal)
    emit([0x011c,tx[S]],"type",S);emit([0x011c,tx[S]],"type",S)
    if extra_types:
        emit([0x011c,tx["I"]],"type","I");emit([0x011c,tx["[I"]],"type","[I")
    emit([0x0062,fx[(E,"shared",S)]],"field_read",E+"->shared:"+S)
    emit([0x0069,fx[(E,"shared",S)]],"field_write",E+"->shared:"+S)
    emit([0x0071,index_method(E,"external"),0],"ordinary_call",E+"->external()V")
    emit([0x0071,index_method(E,"external"),0],"ordinary_call",E+"->external()V")
    emit([0x0077,index_method(E,"external"),0],"range_call",E+"->external()V")
    emit([0x0071,index_method(A,"target"),0],"ordinary_call",A+"->target()V")
    if poly:
        emit([0x0062,fx[(E,"handle",MH)]],"field_read",E+"->handle:"+MH)
        emit([0x10fa,index_method(MH,"invokeExact"),0,px[(V,())]],"polymorphic_call",MH+"->invokeExact([Ljava/lang/Object;)Ljava/lang/Object;")
        emit([0x01fb,index_method(MH,"invokeExact"),0,px[(V,())]],"polymorphic_range_call",MH+"->invokeExact([Ljava/lang/Object;)Ljava/lang/Object;")
        emit([0x00fc,0,0],"custom_call",0);emit([0x00fd,0,0],"custom_range_call",0)
    if handles:
        emit([0x00fe,0],"method_handle",0);emit([0x01fe,1],"method_handle",1);emit([0x00ff,px[(V,())]],"prototype",px[(V,())])
    emit([0x000e])
    align();entries.append((0x2001,3 if orphan else 2,len(data)))
    code_offsets={}
    def body(name,words,registers=2,outs=0):
        align();code_offsets[name]=len(data);data.extend(struct.pack("<HHHHII",registers,0,outs,0,0,len(words)));data.extend(struct.pack("<"+"H"*len(words),*words))
    body("caller",units,2,1 if poly else 0);body("target",[0x000e],0)
    if orphan:body("orphan",[0x001a,sx["repeat"],0x0071,index_method(A,"target"),0,0x000e],1)
    labels["class_data"]=len(data);entries.append((0x2000,1,len(data)))
    defined=[(index,value) for index,value in enumerate(methods) if value[0]==A]
    data.extend(leb(1 if local_field else 0)+b"\0"+leb(len(defined))+b"\0");previous=0;encoded_method_offsets={}
    if local_field:data.extend(leb(fx[(A,"localValue",S)])+leb(9))
    for ordinal,(index,value) in enumerate(defined):
        name=value[1];encoded_method_offsets[name]=len(data)
        data.extend(leb(index-previous)+leb(0x109 if name=="nativeNoBody" else 9)+leb(0 if name=="nativeNoBody" else code_offsets["caller" if name in ["caller","aliasCaller"] else "target"]))
        previous=index
    annotations_off=0
    if bad_annotation:
        labels["bad_annotation"]=len(data);entries.append((0x2004,1,len(data)));data.extend(bytes([3,tx["Lfixture/BadAnnotation;"],0]));align()
        labels["bad_set"]=len(data);entries.append((0x1003,1,len(data)));data.extend(struct.pack("<II",1,labels["bad_annotation"]));labels["bad_directory"]=len(data);entries.append((0x2006,1,len(data)));data.extend(struct.pack("<4I",labels["bad_set"],0,0,0));annotations_off=labels["bad_directory"]
    struct.pack_into("<8I",data,class_off,tx[A],1,tx[O],0,0xffffffff,annotations_off,labels["class_data"],0)
    align();labels["map"]=len(data);entries.append((0x1000,1,len(data)));data.extend(struct.pack("<I",len(entries)))
    for kind,count,offset in entries:data.extend(struct.pack("<HHII",kind,0,count,offset))
    struct.pack_into("<20I",data,32,len(data),112,0x12345678,0,0,labels["map"],len(text),string_off,len(types),type_off,len(protos),proto_off,len(fields),field_off,len(methods),method_off,1,class_off,len(data)-data_off,data_off)
    return finish(data,version),{"case":case,"version":version,"strings":text,"string_indices":sx,"types":types,"type_indices":tx,"prototypes":[[ret,list(args)] for ret,args in protos],"methods":[[owner,name,ret,list(args)] for owner,name,ret,args in methods],"fields":fields,"code_offsets":code_offsets,"encoded_method_offsets":encoded_method_offsets,"labels":labels,"instruction_sites":site_expectations,"insns_units":len(units),"shared_caller_names":["aliasCaller","caller"] if shared else ["caller"]}


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    manifest=[];layouts={}
    def emit(case,data,layout,reference_expected="complete",sdk_expected="accept",reason=None):
        path=OUT/(case+".dex");path.write_bytes(data);layouts[case]=layout
        manifest.append({"path":"tests/fixtures/references/generated/"+path.name,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"reference_build_expected":reference_expected,"format_sdk_expected":sdk_expected,"reason":reason,"claim":"Controlled independent structural DEX; reference binding and global SDK format scope are separate; no installation or full ART type-flow claim"})
    for case in ["classic-035","shared-code-035","orphan-code-035","poly-custom-038","handles-039","nonscalar-string-035","ordinary-unrelated-bad-annotation","poly-custom-unrelated-bad-annotation","defined-field-035","type-names-035","jumbo-string-035"]:
        data,layout=build(case);emit(case,data,layout,sdk_expected="reject_unrelated_annotation" if "unrelated-bad-annotation" in case else "accept")
    classic,layout=build("classic-035");caller=layout["code_offsets"]["caller"];first_call=next(site["pc"] for site in layout["instruction_sites"] if site["label"]=="ordinary_call")
    variants=[("bad-reference-index",caller+16+first_call*2+2,65535,2,"invalid_code_operand","reject"),
              ("bad-invoke-argument-count",caller+16+first_call*2,0x1071,2,"invoke_argument_words","observe_format"),
              ("bad-caller-ins-size",caller+2,1,2,"caller_ins_words","observe_format")]
    for name,at,value,width,reason,sdk in variants:
        changed=bytearray(classic);changed[at:at+width]=value.to_bytes(width,"little")
        if name=="bad-invoke-argument-count":struct.pack_into("<H",changed,caller+6,1)
        emit(name,finish(changed,"035"),layout,"invalid",sdk,reason)
    changed=bytearray(classic);at=layout["encoded_method_offsets"]["caller"]
    _,delta_size=(0,len(leb(next(index for index,value in enumerate(layout["methods"]) if value[0]==A and value[1]=="caller"))))
    code_at=at+delta_size+len(leb(9));encoded=leb(caller+4);require(len(encoded)==len(leb(caller)),"pointer mutant width changed");changed[code_at:code_at+len(encoded)]=encoded
    emit("bad-body-interior-pointer",finish(changed,"035"),layout,"invalid","reject","body_not_physical_start")
    poly,layout=build("poly-custom-038");changed=bytearray(poly);changed[layout["labels"]["call_array"]+1]=0x17
    emit("bad-custom-prefix",finish(changed,"038"),layout,"invalid","reject","custom_prefix")
    changed=bytearray(poly);custom=next(site["pc"] for site in layout["instruction_sites"] if site["label"]=="custom_call");struct.pack_into("<H",changed,layout["code_offsets"]["caller"]+16+custom*2,0x10fc)
    emit("bad-custom-argument-count",finish(changed,"038"),layout,"invalid","observe_format","custom_argument_words")
    changed=bytearray(poly);poly_pc=next(site["pc"] for site in layout["instruction_sites"] if site["label"]=="polymorphic_call");struct.pack_into("<H",changed,layout["code_offsets"]["caller"]+16+poly_pc*2+6,65535)
    emit("bad-poly-proto-index",finish(changed,"038"),layout,"invalid","reject","poly_proto_index")
    (HERE/"layouts.json").write_text(json.dumps(lossless_json(layouts),indent=2,ensure_ascii=True)+"\n",encoding="utf8")
    (HERE/"manifest.json").write_text(json.dumps({"schema_version":"mdd.reference-fixtures.v1","generator":"tests/fixtures/references/generate.py","files":manifest,"source":"hand-authored instruction words and independent Python stdlib DEX writer; not production parser"},indent=2,ensure_ascii=True)+"\n",encoding="utf8")
    print("generated",len(manifest),"reference fixtures")


if __name__=="__main__":main()
