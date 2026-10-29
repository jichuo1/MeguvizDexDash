//! Partial nonempty references in one occurrence must block an all-source query.
use mdd_dex::{definitions::{DefinitionLimits,MethodBody},instructions::CodeLimits,strings::StringLimits};
use mdd_facts::{MetadataFacts,code::CodeFacts,coverage::{CoverageLedger,CoverageRequest,FactLayer},
    definitions::DefinitionFacts,indexes::{FactView,IndexLimits,SelectedScope,SnapshotFactIndex},
    references::{MethodSymbol,ReferenceFacts,ReferenceLimits,TargetKind}};
use mdd_input::{archive::{ArchiveInventory,ArchiveLimits,InventoryPolicy},snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot}};
use mdd_types::{Completeness,ErrorCode,MddError,MddResult};
use serde_json::{Value,json};
use std::{path::PathBuf,process::ExitCode};

fn ensure(ok:bool,msg:&str)->MddResult<()> {
    if ok { Ok(()) } else { Err(MddError::new(ErrorCode::InternalFault,"partial_reference_probe",msg)) }
}
fn run()->MddResult<Value> {
    let args=std::env::args().skip(1).collect::<Vec<_>>();
    ensure(args.len()==3,"two DEX paths and partial occurrence index required")?;
    let partial=args[2].parse::<usize>().map_err(|_|MddError::new(ErrorCode::InvalidArgument,"partial_reference_probe","bad partial index"))?;
    ensure(partial<2,"partial index outside scope")?;
    let inputs=args[..2].iter().map(|p|InputSpec{path:PathBuf::from(p),kind:InputKind::RawDex,expected_sha256:None}).collect::<Vec<_>>();
    let snapshot=Snapshot::capture(&inputs,CaptureLimits::default())?;
    let inv=snapshot.sources().iter().map(|s|ArchiveInventory::build(s,InventoryPolicy::default(),ArchiveLimits::default())).collect::<MddResult<Vec<_>>>()?;
    let scope=SelectedScope::from_inventories(&snapshot,&inv.iter().collect::<Vec<_>>())?;
    let mut refs=Vec::new();
    for (n,inventory) in inv.iter().enumerate() {
        let metadata=MetadataFacts::build(&snapshot,inventory,0,StringLimits::default())?;
        let definitions=DefinitionFacts::build(metadata,DefinitionLimits::default())?;
        let caller=definitions.definitions().method_definitions.iter().find(|m|definitions.definitions().method_references[m.method_idx as usize].method_name=="caller")
            .ok_or_else(||MddError::new(ErrorCode::IncompleteFacts,"partial_reference_probe","caller absent"))?;
        let MethodBody::Present{code_byte_offset,..}=caller.body else { return Err(MddError::new(ErrorCode::IncompleteFacts,"partial_reference_probe","caller body absent")) };
        let code=if n==partial { CodeFacts::build_offsets(&snapshot,inventory,0,&[code_byte_offset.0 as u32],CodeLimits::default())? }
                 else { CodeFacts::build_all_code_items(&snapshot,inventory,0,CodeLimits::default())? };
        refs.push(ReferenceFacts::build(definitions,code,ReferenceLimits::default())?);
    }
    let p=&refs[partial];let full=1-partial;
    ensure(p.coverage().facts==Completeness::Partial && !p.sites().is_empty(),"partial reference facts were empty or complete")?;
    ensure(refs[full].coverage().facts==Completeness::Complete,"full reference facts incomplete")?;
    let idx=p.definitions().metadata().strings().iter().find(|s|s.data.text.strict_utf8().ok().as_deref()==Some("repeat"))
        .ok_or_else(||MddError::new(ErrorCode::IncompleteFacts,"partial_reference_probe","string absent"))?.data.string_idx;
    let target=p.target_id(TargetKind::String,idx)?;
    let local=p.find_target_indexed(&target)?;
    ensure(local==p.find_target_scalar(&target)? && local.coverage==Completeness::Partial && !local.sites.is_empty()
           && !local.absence_proven_within_encoded_operand_scope,"partial matches incorrectly complete or empty")?;
    let rows_error=p.method_call_rows(partial as u32).err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"partial_reference_probe","partial relation returned success"))?;
    ensure(rows_error.code==ErrorCode::IncompleteFacts,"partial relation error differs")?;
    let views=refs.iter().map(|item|FactView::unbuilt(&item.source().dex_occurrence_id).with_references(item)).collect::<Vec<_>>();
    let ledger=CoverageLedger::new(scope.clone(),&views)?;
    let coverage=ledger.evaluate(&CoverageRequest::for_scope(&scope,&[FactLayer::References]))?;
    let terminal=coverage.require_complete().err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"partial_reference_probe","all scope incorrectly complete"))?;
    ensure(coverage.input==Completeness::Complete && coverage.facts==Completeness::Partial && terminal.code==ErrorCode::IncompleteFacts,
           "combined coverage terminal differs")?;
    let index=SnapshotFactIndex::new(scope.clone(),&views,IndexLimits::default())?;
    let symbol=MethodSymbol{owner:"Lfixture/A;".into(),name:"target".into(),prototype:"()V".into()};
    let indexed_error=index.references_to_method_symbol(&symbol).err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"partial_reference_probe","index returned complete success"))?;
    let scalar_error=index.references_to_method_symbol_scalar(&symbol).err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"partial_reference_probe","scalar returned complete success"))?;
    ensure(indexed_error.code==ErrorCode::IncompleteFacts && scalar_error.code==ErrorCode::IncompleteFacts,"query errors differ")?;
    let subset=SelectedScope::from_inventories(&snapshot,&[&inv[full]])?;
    let clean=CoverageLedger::new(subset.clone(),&[views[full].clone()])?.evaluate(&CoverageRequest::for_scope(&subset,&[FactLayer::References]))?;
    clean.require_complete()?;
    ensure(!clean.covers_all_captured_sources,"subset claimed all captured inputs")?;
    Ok(json!({"operation_status":"ok","probe_complete":true,"profile_admitted":false,"snapshot_id":scope.snapshot_id(),
       "partial_index":partial,"full_index":full,"scope":scope,"partial_source":p.source(),"partial_coverage":p.coverage(),
       "partial_sites":p.sites(),"partial_local_target":target,"partial_local_matches":local,"partial_rows_error":rows_error,
       "all_coverage":coverage,"all_terminal":terminal,"indexed_error":indexed_error,"scalar_error":scalar_error,
       "complete_subset":clean,"full_reference_sites":refs[full].sites(),"full_method_rows":refs[full].method_call_rows(full as u32)?}))
}
fn main()->ExitCode {
    match run() {
        Ok(value)=>{println!("{value}");ExitCode::SUCCESS}
        Err(error)=>{println!("{}",json!({"operation_status":"error","error":error,"probe_complete":false}));ExitCode::FAILURE}
    }
}
