use mdd_dex::{definitions::DefinitionLimits,instructions::CodeLimits,strings::StringLimits};
use mdd_facts::{MetadataFacts,code::CodeFacts,definitions::DefinitionFacts,
    raw_fingerprints::{FingerprintLimits,RawCodeEvidence}};
use mdd_input::{archive::{ArchiveInventory,ArchiveLimits,InventoryPolicy},snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot}};
use mdd_types::{ErrorCode,MddError,MddResult};
use serde_json::{json,Value};
use std::{path::PathBuf,process::ExitCode};

fn check(ok:bool,message:&str)->MddResult<()> {if ok {Ok(())} else {Err(MddError::new(ErrorCode::InternalFault,"raw_generation_probe",message))}}
fn run()->MddResult<Value>{
    let args=std::env::args().skip(1).collect::<Vec<_>>();check(args.len()==2,"mutable DEX and replacement required")?;
    let path=PathBuf::from(&args[0]);let spec=InputSpec{path:path.clone(),kind:InputKind::RawDex,expected_sha256:None};
    let a=Snapshot::capture(&[spec.clone()],CaptureLimits::default())?;
    let replacement=std::fs::read(&args[1]).map_err(|e|MddError::new(ErrorCode::InternalFault,"raw_generation_probe",e.to_string()))?;
    std::fs::write(&path,replacement).map_err(|e|MddError::new(ErrorCode::InternalFault,"raw_generation_probe",e.to_string()))?;
    let b=Snapshot::capture(&[spec],CaptureLimits::default())?;
    check(a.manifest().snapshot_id!=b.manifest().snapshot_id && a.sources()[0].identity().content_id!=b.sources()[0].identity().content_id,"generations collapsed")?;
    let ai=ArchiveInventory::build(&a.sources()[0],InventoryPolicy::default(),ArchiveLimits::default())?;
    let bi=ArchiveInventory::build(&b.sources()[0],InventoryPolicy::default(),ArchiveLimits::default())?;
    let am=MetadataFacts::build(&a,&ai,0,StringLimits::default())?;let bm=MetadataFacts::build(&b,&bi,0,StringLimits::default())?;
    let ad=DefinitionFacts::build(am,DefinitionLimits::default())?;let bd=DefinitionFacts::build(bm,DefinitionLimits::default())?;
    let ac=CodeFacts::build_all_code_items(&a,&ai,0,CodeLimits::default())?;let bc=CodeFacts::build_all_code_items(&b,&bi,0,CodeLimits::default())?;
    let ae=RawCodeEvidence::build(&ad,&ac,FingerprintLimits::default())?;let be=RawCodeEvidence::build(&bd,&bc,FingerprintLimits::default())?;
    let ar=ae.methods().iter().find(|m|m.method.local_index==0).ok_or_else(||MddError::new(ErrorCode::InternalFault,"raw_generation_probe","old caller absent"))?;
    let br=be.methods().iter().find(|m|m.method.local_index==0).ok_or_else(||MddError::new(ErrorCode::InternalFault,"raw_generation_probe","new caller absent"))?;
    let an=ae.methods().iter().find(|m|m.method.local_index==1).ok_or_else(||MddError::new(ErrorCode::InternalFault,"raw_generation_probe","old native absent"))?;
    let bn=be.methods().iter().find(|m|m.method.local_index==1).ok_or_else(||MddError::new(ErrorCode::InternalFault,"raw_generation_probe","new native absent"))?;
    let old=ae.raw_method_body(&ar.method)?.ok_or_else(||MddError::new(ErrorCode::InternalFault,"raw_generation_probe","old body absent"))?;
    let new=be.raw_method_body(&br.method)?.ok_or_else(||MddError::new(ErrorCode::InternalFault,"raw_generation_probe","new body absent"))?;
    check(old!=new && ae.raw_method_body(&an.method)?.is_none() && be.raw_method_body(&bn.method)?.is_none(),"raw body/no-body semantics differ")?;
    let foreign_a=ae.raw_method_body(&br.method).err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"raw_generation_probe","foreign method accepted"))?;
    let foreign_b=be.raw_method_body(&ar.method).err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"raw_generation_probe","foreign method accepted"))?;
    let mixed_a=RawCodeEvidence::build(&ad,&bc,FingerprintLimits::default()).err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"raw_generation_probe","mixed facts accepted"))?;
    let mixed_b=RawCodeEvidence::build(&bd,&ac,FingerprintLimits::default()).err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"raw_generation_probe","mixed facts accepted"))?;
    check([&foreign_a,&foreign_b,&mixed_a,&mixed_b].iter().all(|e|e.code==ErrorCode::InvalidArgument),"foreign generation error differs")?;
    let old_digest=ae.ordered_digest(&[(&ar.method,b"caller\0"),(&an.method,b"native\0")],4096)?;
    let new_digest=be.ordered_digest(&[(&br.method,b"caller\0"),(&bn.method,b"native\0")],4096)?;
    Ok(json!({"operation_status":"ok","profile_admitted":false,"disk_rewritten_between_captures":true,
      "a_snapshot":a.manifest(),"b_snapshot":b.manifest(),"a_raw":ae,"b_raw":be,
      "old_caller_bytes":old,"new_caller_bytes":new,"old_native_is_none":true,"new_native_is_none":true,
      "old_recipe_sha256":old_digest,"new_recipe_sha256":new_digest,
      "foreign_a":foreign_a,"foreign_b":foreign_b,"mixed_a":mixed_a,"mixed_b":mixed_b}))
}
fn main()->ExitCode{match run(){Ok(v)=>{println!("{v}");ExitCode::SUCCESS}Err(e)=>{println!("{}",json!({"operation_status":"error","error":e}));ExitCode::FAILURE}}}
