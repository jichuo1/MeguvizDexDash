use mdd_facts::{coverage::{CoverageLedger,CoverageRequest,InputNeed}, indexes::SelectedScope,
    raw_fingerprints::ResourceByteEvidence};
use mdd_input::{archive::{ArchiveInventory,ArchiveLimits,InventoryPolicy},snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot}};
use mdd_types::{Completeness,ErrorCode,MddError,MddResult};
use serde_json::{json,Value};
use std::{path::PathBuf,process::ExitCode};

fn check(ok:bool,message:&str)->MddResult<()> { if ok {Ok(())} else {Err(MddError::new(ErrorCode::InternalFault,"resource_scope_probe",message))} }
fn run()->MddResult<Value>{
    let path=PathBuf::from(std::env::args().nth(1).ok_or_else(||MddError::new(ErrorCode::InvalidArgument,"resource_scope_probe","APK required"))?);
    let spec=InputSpec{path:path.clone(),kind:InputKind::Apk,expected_sha256:None};
    let snapshot=Snapshot::capture(&[spec.clone(),spec],CaptureLimits::default())?;
    std::fs::write(&path,b"mutation-after-capture").map_err(|e|MddError::new(ErrorCode::InternalFault,"resource_scope_probe",e.to_string()))?;
    let inv=snapshot.sources().iter().map(|s|ArchiveInventory::build(s,InventoryPolicy::default(),ArchiveLimits::default())).collect::<MddResult<Vec<_>>>()?;
    let scope=SelectedScope::from_inventories(&snapshot,&inv.iter().collect::<Vec<_>>())?;
    let selected=SelectedScope::from_inventories(&snapshot,&[&inv[0]])?;
    let mut resources=Vec::new();
    for inventory in &inv {
        for member in &inventory.manifest().members {
            if member.raw_name.starts_with(b"res/") {
                resources.push(ResourceByteEvidence::build(&snapshot,inventory,&member.member_id)?);
            }
        }
    }
    check(resources.len()==6,"expected six resource occurrences")?;
    let ids=resources.iter().map(|r|r.member().member_id.clone()).collect::<Vec<_>>();
    let unique=ids.iter().collect::<std::collections::BTreeSet<_>>();
    check(unique.len()==6,"physical/source member identity collapsed")?;
    let mut req=CoverageRequest::for_scope(&scope,&[]);req.input=InputNeed::SelectedInventory;req.required_resource_members=ids.clone();
    let mut ledger=CoverageLedger::new(scope.clone(),&[])?;
    ledger.record_resource(&resources[0])?;
    let before=ledger.evaluate(&req)?;
    check(before.facts==Completeness::Unknown && before.require_complete().is_err(),"missing members became complete")?;
    for resource in &resources[1..] {ledger.record_resource(resource)?;}
    let after=ledger.evaluate(&req)?;
    check(after.input==Completeness::Complete && after.facts==Completeness::Complete && after.covers_all_captured_sources,"complete resource scope differs")?;
    after.require_complete()?;
    let mut subledger=CoverageLedger::new(selected.clone(),&[])?;
    let foreign=subledger.record_resource(&resources[3]).err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"resource_scope_probe","foreign occurrence accepted"))?;
    check(foreign.code==ErrorCode::InvalidArgument,"foreign source error differs")?;
    for resource in &resources[..3] {subledger.record_resource(resource)?;}
    let mut subreq=CoverageRequest::for_scope(&selected,&[]);subreq.input=InputNeed::SelectedInventory;subreq.required_resource_members=ids[..3].to_vec();
    let subset=subledger.evaluate(&subreq)?;subset.require_complete()?;
    check(!subset.covers_all_captured_sources,"subset claimed all sources")?;
    let output=resources.iter().map(|r|json!({"member":r.member(),"content_id":r.content_id(),"sha256":r.sha256(),"bytes":r.bytes()})).collect::<Vec<_>>();
    Ok(json!({"operation_status":"ok","profile_admitted":false,"snapshot_id":scope.snapshot_id(),
      "scope":scope,"resources":output,"before":before,"after":after,"subset":subset,"foreign_error":foreign,
      "mutation_after_capture":true}))
}
fn main()->ExitCode{match run(){Ok(v)=>{println!("{v}");ExitCode::SUCCESS} Err(e)=>{println!("{}",json!({"operation_status":"error","error":e}));ExitCode::FAILURE}}}
