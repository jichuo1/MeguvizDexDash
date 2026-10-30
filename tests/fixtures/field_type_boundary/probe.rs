//! Source-bound field/type site and scalar/index comparison on mixed DEX.
use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits};
use mdd_facts::{
    MetadataFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    indexes::{FactView, IndexLimits, SelectedScope, SnapshotFactIndex},
    references::{ReferenceFacts, ReferenceLimits, TargetKind},
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{path::PathBuf, process::ExitCode};

fn ensure(ok: bool, message: &str) -> MddResult<()> {
    if ok { Ok(()) } else { Err(MddError::new(ErrorCode::InternalFault, "field_type_probe", message)) }
}
fn run() -> MddResult<Value> {
    let paths = std::env::args_os().skip(1).map(PathBuf::from).collect::<Vec<_>>();
    ensure(paths.len() == 3, "three explicit source occurrences required")?;
    let inputs = paths.into_iter().map(|path| InputSpec { path, kind: InputKind::RawDex, expected_sha256: None }).collect::<Vec<_>>();
    let snapshot = Snapshot::capture(&inputs, CaptureLimits::default())?;
    let inventories = snapshot.sources().iter().map(|source| ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())).collect::<MddResult<Vec<_>>>()?;
    let scope = SelectedScope::from_inventories(&snapshot, &inventories.iter().collect::<Vec<_>>())?;
    let mut refs = Vec::new();
    for inventory in &inventories {
        let metadata = MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default())?;
        let defs = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
        let code = CodeFacts::build_all_code_items(&snapshot, inventory, 0, CodeLimits::default())?;
        refs.push(ReferenceFacts::build(defs, code, ReferenceLimits::default())?);
    }
    let views = refs.iter().map(|item| FactView::unbuilt(&item.source().dex_occurrence_id).with_references(item)).collect::<Vec<_>>();
    let index = SnapshotFactIndex::new(scope.clone(), &views, IndexLimits::default())?;
    let mut ids = Vec::new();
    let mut occurrences = Vec::new();
    for (ordinal, item) in refs.iter().enumerate() {
        let field = item.definitions().definitions().field_references.iter()
            .find(|f| f.descriptor == "Lfixture/External;->shared:Ljava/lang/String;")
            .ok_or_else(|| MddError::new(ErrorCode::IncompleteFacts, "field_type_probe", "field absent"))?;
        let ty = item.definitions().metadata().types().iter()
            .find(|t| t.data.descriptor == "Ljava/lang/String;")
            .ok_or_else(|| MddError::new(ErrorCode::IncompleteFacts, "field_type_probe", "type absent"))?;
        let field_id = item.target_id(TargetKind::Field, field.field_idx)?;
        let type_id = item.target_id(TargetKind::Type, ty.data.type_idx)?;
        let field_local = item.find_target_scalar(&field_id)?;
        let type_local = item.find_target_scalar(&type_id)?;
        ensure(index.references_local(&field_id)? == field_local && index.references_local(&type_id)? == type_local, "local indexed/scalar mismatch")?;
        ids.push((field_id, type_id));
        occurrences.push(json!({"selected": &scope.dexes()[ordinal], "source": item.source(),
            "pool": item.definitions().metadata().string_pool(), "field_index": field.field_idx,
            "type_index": ty.data.type_idx, "field_local": field_local, "type_local": type_local,
            "sites": item.sites(), "field_rows": item.method_field_rows(ordinal as u32)?,
            "type_rows": item.method_type_rows(ordinal as u32)?}));
    }
    let foreign_field = refs[1].find_target_indexed(&ids[0].0).err().ok_or_else(|| MddError::new(ErrorCode::InternalFault, "field_type_probe", "foreign field accepted"))?;
    let foreign_type = refs[1].find_target_indexed(&ids[0].1).err().ok_or_else(|| MddError::new(ErrorCode::InternalFault, "field_type_probe", "foreign type accepted"))?;
    ensure(foreign_field.code == ErrorCode::InvalidArgument && foreign_type.code == ErrorCode::InvalidArgument, "foreign target wrong terminal")?;
    Ok(json!({"operation_status":"ok", "probe_complete":true, "snapshot_id":scope.snapshot_id(),
        "scope_id":scope.scope_id(), "occurrences":occurrences, "foreign_field":foreign_field,
        "foreign_type":foreign_type, "profile_admitted":false}))
}
fn main() -> ExitCode {
    match run() {
        Ok(value) => { println!("{value}"); ExitCode::SUCCESS }
        Err(error) => { println!("{}", json!({"operation_status":"error", "error":error, "probe_complete":false})); ExitCode::FAILURE }
    }
}
