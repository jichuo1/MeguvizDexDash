//! Bound dynamic and orphan reference facts from mixed DEX occurrences.
use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits};
use mdd_facts::{MetadataFacts, code::CodeFacts, definitions::DefinitionFacts,
    indexes::{FactView, IndexLimits, SelectedScope, SnapshotFactIndex},
    references::{ReferenceFacts, ReferenceLimits, TargetKind}};
use mdd_input::{archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot}};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value,json};
use std::{path::PathBuf, process::ExitCode};

fn ensure(ok:bool, message:&str)->MddResult<()> {
    if ok { Ok(()) } else { Err(MddError::new(ErrorCode::InternalFault,"dynamic_source_probe",message)) }
}
fn run()->MddResult<Value> {
    let paths=std::env::args_os().skip(1).map(PathBuf::from).collect::<Vec<_>>();
    ensure(paths.len()==4,"four source occurrences required")?;
    let inputs=paths.into_iter().map(|path|InputSpec{path,kind:InputKind::RawDex,expected_sha256:None}).collect::<Vec<_>>();
    let snapshot=Snapshot::capture(&inputs,CaptureLimits::default())?;
    let inventories=snapshot.sources().iter().map(|source|ArchiveInventory::build(source,InventoryPolicy::default(),ArchiveLimits::default())).collect::<MddResult<Vec<_>>>()?;
    let scope=SelectedScope::from_inventories(&snapshot,&inventories.iter().collect::<Vec<_>>())?;
    let mut refs=Vec::new();
    let mut quota_errors=Vec::new();
    for inv in &inventories {
        let metadata=MetadataFacts::build(&snapshot,inv,0,StringLimits::default())?;
        let defs=DefinitionFacts::build(metadata,DefinitionLimits::default())?;
        let code=CodeFacts::build_all_code_items(&snapshot,inv,0,CodeLimits::default())?;
        let limits=ReferenceLimits{max_sites:0,..ReferenceLimits::default()};
        let error=match ReferenceFacts::build(defs.clone(),code.clone(),limits) {
            Ok(_) => return Err(MddError::new(ErrorCode::InternalFault,"dynamic_source_probe","zero-site quota unexpectedly succeeded")),
            Err(error) => error,
        };
        ensure(error.code == ErrorCode::QuotaExceeded,"zero-site quota terminal differs")?;
        quota_errors.push(error);
        refs.push(ReferenceFacts::build(defs,code,ReferenceLimits::default())?);
    }
    let views=refs.iter().map(|item|FactView::unbuilt(&item.source().dex_occurrence_id).with_references(item)).collect::<Vec<_>>();
    let index=SnapshotFactIndex::new(scope.clone(),&views,IndexLimits::default())?;
    let mut occurrences=Vec::new();
    for (n,item) in refs.iter().enumerate() {
        let mut targets=Vec::new();
        for site in item.sites() {
            let target=item.target_id(site.target_kind,site.target_local_index)?;
            let expected=item.find_target_scalar(&target)?;
            ensure(item.find_target_indexed(&target)? == expected && index.references_local(&target)? == expected,
                   "source target indexed/scalar mismatch")?;
            targets.push(json!({"target":target,"matches":expected}));
        }
        occurrences.push(json!({"selected":&scope.dexes()[n],"source":item.source(),
            "pool":item.definitions().metadata().string_pool(),"coverage":item.coverage(),"sites":item.sites(),
            "dynamic_calls":item.dynamic_calls(),"handles":item.method_handle_metadata(),
            "call_sites":item.call_site_metadata(),"method_call_rows":item.method_call_rows(n as u32)?,
            "method_field_rows":item.method_field_rows(n as u32)?,"target_checks":targets}));
    }
    let id=refs[0].target_id(TargetKind::CallSite,0)?;
    let foreign=refs[3].find_target_indexed(&id).err().ok_or_else(||MddError::new(ErrorCode::InternalFault,"dynamic_source_probe","foreign occurrence accepted"))?;
    ensure(foreign.code==ErrorCode::InvalidArgument,"foreign occurrence error differs")?;
    Ok(json!({"operation_status":"ok","probe_complete":true,"snapshot_id":scope.snapshot_id(),
        "occurrences":occurrences,"foreign_call_site":foreign,"quota_errors":quota_errors,"profile_admitted":false}))
}
fn main()->ExitCode {
    match run() {
        Ok(value)=>{println!("{value}");ExitCode::SUCCESS}
        Err(error)=>{println!("{}",json!({"operation_status":"error","error":error,"probe_complete":false}));ExitCode::FAILURE}
    }
}
