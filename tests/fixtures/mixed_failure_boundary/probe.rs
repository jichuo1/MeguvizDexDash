//! Coverage with a real malformed source and a valid sibling in the same snapshot.
use mdd_dex::{definitions::DefinitionLimits,instructions::CodeLimits,strings::StringLimits};
use mdd_facts::{MetadataFacts,code::CodeFacts,coverage::{CoverageLedger,CoverageRequest,FactLayer},
    definitions::DefinitionFacts,indexes::{FactView,SelectedScope},references::{ReferenceFacts,ReferenceLimits}};
use mdd_input::{archive::{ArchiveInventory,ArchiveLimits,InventoryPolicy},snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot}};
use mdd_types::{Completeness,ErrorCode,MddError,MddResult};
use serde_json::{Value,json};
use std::{path::PathBuf,process::ExitCode};

fn ensure(ok:bool, message:&str)->MddResult<()> {
    if ok { Ok(()) } else { Err(MddError::new(ErrorCode::InternalFault,"mixed_failure_probe",message)) }
}
fn run()->MddResult<Value> {
    let paths=std::env::args_os().skip(1).map(PathBuf::from).collect::<Vec<_>>();
    ensure(paths.len()==2,"two input sources required")?;
    let inputs=paths.into_iter().map(|path|InputSpec{path,kind:InputKind::RawDex,expected_sha256:None}).collect::<Vec<_>>();
    let snapshot=Snapshot::capture(&inputs,CaptureLimits::default())?;
    let inventories=snapshot.sources().iter().map(|source|ArchiveInventory::build(source,InventoryPolicy::default(),ArchiveLimits::default())).collect::<MddResult<Vec<_>>>()?;
    let scope=SelectedScope::from_inventories(&snapshot,&inventories.iter().collect::<Vec<_>>())?;
    let mut defs=Vec::new();let mut refs=Vec::new();let mut errors=Vec::new();
    for inv in &inventories {
        let metadata=MetadataFacts::build(&snapshot,inv,0,StringLimits::default())?;
        let definitions=DefinitionFacts::build(metadata,DefinitionLimits::default())?;
        match CodeFacts::build_all_code_items(&snapshot,inv,0,CodeLimits::default()) {
            Ok(code)=>{refs.push(Some(ReferenceFacts::build(definitions.clone(),code,ReferenceLimits::default())?));errors.push(None);},
            Err(error)=>{ensure(error.code==ErrorCode::InvalidInput,"bad input did not produce INVALID_INPUT")?;refs.push(None);errors.push(Some(error));},
        }
        defs.push(definitions);
    }
    let valid=refs.iter().position(Option::is_some).ok_or_else(||MddError::new(ErrorCode::InternalFault,"mixed_failure_probe","missing valid source"))?;
    let bad=errors.iter().position(Option::is_some).ok_or_else(||MddError::new(ErrorCode::InternalFault,"mixed_failure_probe","missing corrupt source"))?;
    ensure(valid!=bad && refs.iter().filter(|v|v.is_some()).count()==1 && errors.iter().filter(|e|e.is_some()).count()==1,
           "unexpected success/failure roster")?;
    let mut views=Vec::new();
    for n in 0..2 {
        let occurrence=scope.dexes()[n].dex_occurrence_id.clone();
        let view=FactView::unbuilt(occurrence).with_definitions(&defs[n]);
        views.push(if let Some(fact)=&refs[n] { view.with_references(fact) } else { view });
    }
    let original=errors[bad].as_ref().ok_or_else(||MddError::new(ErrorCode::InternalFault,"mixed_failure_probe","missing error"))?;
    let mut ledger=CoverageLedger::new(scope.clone(),&views)?;
    ledger.record_failure(&scope.dexes()[bad].dex_occurrence_id,FactLayer::CodeProjection,original.clone())?;
    let overwrite=ledger.record_failure(&scope.dexes()[bad].dex_occurrence_id,FactLayer::CodeProjection,
        MddError::new(ErrorCode::UnsupportedCapability,"fake.fallback","attempted overwrite")).err()
        .ok_or_else(||MddError::new(ErrorCode::InternalFault,"mixed_failure_probe","failure overwrite accepted"))?;
    ensure(overwrite.code==ErrorCode::InvalidArgument,"wrong overwrite error")?;
    let report=ledger.evaluate(&CoverageRequest::for_scope(&scope,&[FactLayer::References]))?;
    ensure(report.input==Completeness::Complete && report.facts!=Completeness::Complete,"whole scope incorrectly complete")?;
    let terminal=report.require_complete().err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"mixed_failure_probe","bad scope succeeded"))?;
    ensure(terminal.code==original.code && terminal.stage==original.stage && terminal.message==original.message,
           "real error not preserved")?;
    let subset=SelectedScope::from_inventories(&snapshot,&[&inventories[valid]])?;
    let single=CoverageLedger::new(subset.clone(),&[views[valid].clone()])?
        .evaluate(&CoverageRequest::for_scope(&subset,&[FactLayer::References]))?;
    single.require_complete()?;
    ensure(single.input==Completeness::Complete && single.facts==Completeness::Complete
           && !single.covers_all_captured_sources && single.selected_dex_occurrences.len()==1,"valid subset scope differs")?;
    let ok=refs[valid].as_ref().ok_or_else(||MddError::new(ErrorCode::InternalFault,"mixed_failure_probe","missing reference"))?;
    Ok(json!({"operation_status":"ok","probe_complete":true,"profile_admitted":false,"snapshot_id":scope.snapshot_id(),
       "all_scope":scope,"valid_index":valid,"bad_index":bad,"original_error":original,"overwrite_error":overwrite,
       "all_coverage":report,"all_terminal":terminal,"valid_subset_coverage":single,
       "valid_reference_source":ok.source(),"valid_reference_sites":ok.sites(),"valid_method_calls":ok.method_call_rows(valid as u32)?}))
}
fn main()->ExitCode {
    match run() {
        Ok(value)=>{println!("{value}");ExitCode::SUCCESS}
        Err(error)=>{println!("{}",json!({"operation_status":"error","error":error,"probe_complete":false}));ExitCode::FAILURE}
    }
}
