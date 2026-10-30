use mdd_facts::{coverage::{CoverageLedger,CoverageRequest,InputNeed}, indexes::SelectedScope,
    raw_fingerprints::ResourceByteEvidence};
use mdd_input::{archive::{ArchiveInventory,ArchiveLimits,InventoryPolicy},snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot}};
use mdd_types::{Completeness,ErrorCode,MddError,MddResult};
use serde_json::{json,Value};
use std::{path::PathBuf,process::ExitCode};

fn check(ok:bool,message:&str)->MddResult<()> { if ok {Ok(())} else {Err(MddError::new(ErrorCode::InternalFault,"resource_generation_probe",message))} }
fn run()->MddResult<Value>{
    let args=std::env::args().skip(1).collect::<Vec<_>>();
    check(args.len()==2,"mutable APK and replacement bytes required")?;
    let path=PathBuf::from(&args[0]);let replacement=PathBuf::from(&args[1]);
    let spec=InputSpec{path:path.clone(),kind:InputKind::Apk,expected_sha256:None};
    let a=Snapshot::capture(&[spec.clone()],CaptureLimits::default())?;
    let new_bytes=std::fs::read(&replacement).map_err(|e|MddError::new(ErrorCode::InternalFault,"resource_generation_probe",e.to_string()))?;
    std::fs::write(&path,new_bytes).map_err(|e|MddError::new(ErrorCode::InternalFault,"resource_generation_probe",e.to_string()))?;
    let b=Snapshot::capture(&[spec],CaptureLimits::default())?;
    check(a.manifest().snapshot_id!=b.manifest().snapshot_id && a.sources()[0].identity().content_id!=b.sources()[0].identity().content_id,
          "snapshot generations collapsed")?;
    let ai=ArchiveInventory::build(&a.sources()[0],InventoryPolicy::default(),ArchiveLimits::default())?;
    let bi=ArchiveInventory::build(&b.sources()[0],InventoryPolicy::default(),ArchiveLimits::default())?;
    let ascope=SelectedScope::from_inventories(&a,&[&ai])?;let bscope=SelectedScope::from_inventories(&b,&[&bi])?;
    let mut ar=Vec::new();let mut br=Vec::new();
    for member in &ai.manifest().members {if member.raw_name.starts_with(b"res/") {ar.push(ResourceByteEvidence::build(&a,&ai,&member.member_id)?);}}
    for member in &bi.manifest().members {if member.raw_name.starts_with(b"res/") {br.push(ResourceByteEvidence::build(&b,&bi,&member.member_id)?);}}
    check(ar.len()==3 && br.len()==3,"expected three physical resources in each generation")?;
    let aid=ar.iter().map(|r|r.member().member_id.clone()).collect::<Vec<_>>();
    let bid=br.iter().map(|r|r.member().member_id.clone()).collect::<Vec<_>>();
    let mut areq=CoverageRequest::for_scope(&ascope,&[]);areq.input=InputNeed::SelectedInventory;areq.required_resource_members=aid.clone();
    let mut breq=CoverageRequest::for_scope(&bscope,&[]);breq.input=InputNeed::SelectedInventory;breq.required_resource_members=bid.clone();
    let mut al=CoverageLedger::new(ascope.clone(),&[])?;let mut bl=CoverageLedger::new(bscope.clone(),&[])?;
    for r in &ar[..2] {al.record_resource(r)?;} for r in &br[..2] {bl.record_resource(r)?;}
    let before_a=al.evaluate(&areq)?;let before_b=bl.evaluate(&breq)?;
    let foreign_a=al.record_resource(&br[2]).err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"resource_generation_probe","new resource entered old snapshot"))?;
    let foreign_b=bl.record_resource(&ar[2]).err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"resource_generation_probe","old resource entered new snapshot"))?;
    check(foreign_a.code==ErrorCode::InvalidArgument && foreign_b.code==ErrorCode::InvalidArgument,"foreign snapshot error differs")?;
    let rejected_a=al.evaluate(&areq)?;let rejected_b=bl.evaluate(&breq)?;
    check(before_a.facts==Completeness::Unknown && before_b.facts==Completeness::Unknown && rejected_a.facts==Completeness::Unknown
          && rejected_b.facts==Completeness::Unknown && rejected_a.require_complete().is_err() && rejected_b.require_complete().is_err(),
          "foreign resource promoted missing coverage")?;
    al.record_resource(&ar[2])?;bl.record_resource(&br[2])?;
    let after_a=al.evaluate(&areq)?;let after_b=bl.evaluate(&breq)?;after_a.require_complete()?;after_b.require_complete()?;
    check(after_a.facts==Completeness::Complete && after_b.facts==Completeness::Complete,"own generation coverage not complete")?;
    let rows=|v:&[ResourceByteEvidence]|v.iter().map(|r|json!({"member":r.member(),"snapshot_id":r.snapshot_id(),"content_id":r.content_id(),"sha256":r.sha256(),"bytes":r.bytes()})).collect::<Vec<_>>();
    Ok(json!({"operation_status":"ok","profile_admitted":false,"disk_rewritten_between_captures":true,
      "a_scope":ascope,"b_scope":bscope,"a_resources":rows(&ar),"b_resources":rows(&br),
      "a_before":before_a,"b_before":before_b,"a_rejected":rejected_a,"b_rejected":rejected_b,
      "a_after":after_a,"b_after":after_b,"foreign_a":foreign_a,"foreign_b":foreign_b}))
}
fn main()->ExitCode{match run(){Ok(v)=>{println!("{v}");ExitCode::SUCCESS} Err(e)=>{println!("{}",json!({"operation_status":"error","error":e}));ExitCode::FAILURE}}}
