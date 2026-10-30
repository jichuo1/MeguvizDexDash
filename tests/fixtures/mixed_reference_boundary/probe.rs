//! Probe same symbols across mixed DEX occurrences without merging identities.
use mdd_dex::{definitions::DefinitionLimits,instructions::CodeLimits,strings::StringLimits};
use mdd_facts::{MetadataFacts,code::CodeFacts,definitions::{ClassResolution,DefinitionFacts,resolve_class},
    indexes::{FactView,IndexLimits,SelectedScope,SnapshotFactIndex},references::{MethodSymbol,ReferenceFacts,ReferenceLimits,TargetKind}};
use mdd_input::{archive::{ArchiveInventory,ArchiveLimits,InventoryPolicy},snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot}};
use mdd_types::{ErrorCode,MddError,MddResult};
use serde_json::{Value,json};
use std::{path::PathBuf,process::ExitCode};

fn ensure(ok:bool,message:&str)->MddResult<()> {
    if ok { Ok(()) } else { Err(MddError::new(ErrorCode::InternalFault,"mixed_reference_probe",message)) }
}
fn run()->MddResult<Value> {
    let paths=std::env::args_os().skip(1).map(PathBuf::from).collect::<Vec<_>>();
    ensure(paths.len()==3,"three explicit source occurrences required")?;
    let inputs=paths.into_iter().map(|path|InputSpec{path,kind:InputKind::RawDex,expected_sha256:None}).collect::<Vec<_>>();
    let snapshot=Snapshot::capture(&inputs,CaptureLimits::default())?;
    let inventories=snapshot.sources().iter().map(|source|ArchiveInventory::build(source,InventoryPolicy::default(),ArchiveLimits::default())).collect::<MddResult<Vec<_>>>()?;
    let scope=SelectedScope::from_inventories(&snapshot,&inventories.iter().collect::<Vec<_>>())?;
    let mut definitions=Vec::new();
    let mut references=Vec::new();
    for inventory in &inventories {
        let metadata=MetadataFacts::build(&snapshot,inventory,0,StringLimits::default())?;
        let defs=DefinitionFacts::build(metadata,DefinitionLimits::default())?;
        let code=CodeFacts::build_all_code_items(&snapshot,inventory,0,CodeLimits::default())?;
        references.push(ReferenceFacts::build(defs.clone(),code,ReferenceLimits::default())?);
        definitions.push(defs);
    }
    let class_matches=match resolve_class(&definitions,"Lfixture/A;")? {
        ClassResolution::Ambiguous(matches) => matches.into_iter().map(|item|json!({"dex_occurrence_id":item.facts.metadata().source().dex_occurrence_id,
            "class_def_idx":item.class.class_def_idx})).collect::<Vec<_>>(),
        _ => return Err(MddError::new(ErrorCode::InternalFault,"mixed_reference_probe","duplicate class was not ambiguous")),
    };
    let views=references.iter().map(|item|FactView::unbuilt(&item.source().dex_occurrence_id).with_references(item)).collect::<Vec<_>>();
    let index=SnapshotFactIndex::new(scope.clone(),&views,IndexLimits::default())?;
    let symbol=MethodSymbol{owner:"Lfixture/A;".into(),name:"target".into(),prototype:"()V".into()};
    let indexed=index.references_to_method_symbol(&symbol)?;
    let scalar=index.references_to_method_symbol_scalar(&symbol)?;
    ensure(indexed.sites==scalar.sites,"global symbol index/scalar differ")?;
    let mut occurrences=Vec::new();
    let mut target_ids=Vec::new();
    for (number,item) in references.iter().enumerate() {
        let target=definitions[number].definitions().method_references.iter()
            .find(|method|method.class_descriptor==symbol.owner && method.method_name==symbol.name)
            .ok_or_else(||MddError::new(ErrorCode::IncompleteFacts,"mixed_reference_probe","target method absent"))?;
        let target_id=item.target_id(TargetKind::Method,target.method_idx)?;
        let local=item.find_target_scalar(&target_id)?;
        ensure(index.references_local(&target_id)?==local,"local index/scalar differ")?;
        target_ids.push(target_id);
        occurrences.push(json!({"selected":&scope.dexes()[number],"source":item.source(),
            "pool":item.definitions().metadata().string_pool(),"target_index":target.method_idx,
            "local_target":local,"all_sites":item.sites(),"method_call_rows":item.method_call_rows(number as u32)?}));
    }
    let cross_error=references[1].find_target_indexed(&target_ids[0]).err()
        .ok_or_else(||MddError::new(ErrorCode::InternalFault,"mixed_reference_probe","foreign occurrence accepted"))?;
    ensure(cross_error.code==ErrorCode::InvalidArgument,"foreign occurrence returned wrong error")?;
    Ok(json!({"operation_status":"ok","probe_complete":true,"snapshot_id":scope.snapshot_id(),"scope_id":scope.scope_id(),
        "class_resolution":{"status":"ambiguous","matches":class_matches},"occurrences":occurrences,
        "target_symbol":symbol,"global_indexed":indexed,"cross_occurrence_error":cross_error,"profile_admitted":false}))
}
fn main()->ExitCode {
    match run() {
        Ok(value)=>{println!("{value}");ExitCode::SUCCESS}
        Err(error)=>{println!("{}",json!({"operation_status":"error","error":error,"probe_complete":false}));ExitCode::FAILURE}
    }
}
