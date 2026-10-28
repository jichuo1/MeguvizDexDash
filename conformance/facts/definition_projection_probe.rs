//! Small real-API probe for definition rows and selected-source numbering.
use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
use mdd_facts::{MetadataFacts, definitions::DefinitionFacts, indexes::SelectedScope};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{path::PathBuf, process::ExitCode};

fn run() -> MddResult<Value> {
    let path = std::env::args_os().nth(1).map(PathBuf::from).ok_or_else(|| {
        MddError::new(ErrorCode::InvalidArgument, "fact_probe", "missing fixture")
    })?;
    let specs = (0..2)
        .map(|_| InputSpec { path: path.clone(), kind: InputKind::RawDex, expected_sha256: None })
        .collect::<Vec<_>>();
    let snapshot = Snapshot::capture(&specs, CaptureLimits::default())?;
    let inventories = snapshot.sources().iter().map(|source| {
        ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
    }).collect::<MddResult<Vec<_>>>()?;
    let refs = inventories.iter().collect::<Vec<_>>();
    let scope = SelectedScope::from_inventories(&snapshot, &refs)?;
    if scope.dexes().len() != 2 || !scope.roster_complete() || !scope.covers_all_captured_sources() {
        return Err(MddError::new(ErrorCode::IncompleteFacts, "fact_probe", "expected two complete occurrences"));
    }
    let mut outputs = Vec::new();
    for (index, inventory) in inventories.iter().enumerate() {
        let metadata = MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default())?;
        let facts = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
        let selected = &scope.dexes()[index];
        if facts.metadata().source().dex_occurrence_id != selected.dex_occurrence_id {
            return Err(MddError::new(ErrorCode::InternalFault, "fact_probe", "source-to-catalog binding mismatch"));
        }
        outputs.push(json!({"selected": selected, "fact_source": facts.metadata().source(),
            "class_fields": facts.class_field_rows(selected.file_id),
            "class_methods": facts.class_method_rows(selected.file_id),
            "class_interfaces": facts.class_interface_rows(selected.file_id)}));
    }
    Ok(json!({"operation_status":"ok", "probe_complete":true,
        "snapshot_id":scope.snapshot_id(), "scope_id":scope.scope_id(),
        "selected_occurrences":outputs, "profile_admitted":false}))
}

fn main() -> ExitCode {
    match run() {
        Ok(value) => { println!("{value}"); ExitCode::SUCCESS }
        Err(error) => { eprintln!("{error:?}"); ExitCode::FAILURE }
    }
}
