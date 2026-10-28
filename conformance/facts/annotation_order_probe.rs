//! Observe ordered native annotation rows for two distinct source occurrences.
use mdd_dex::{annotations::AnnotationLimits, definitions::DefinitionLimits, strings::StringLimits};
use mdd_facts::{MetadataFacts, annotations::AnnotationFacts, definitions::DefinitionFacts, indexes::SelectedScope};
use mdd_input::{archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
                snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot}};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{path::PathBuf, process::ExitCode};

fn run() -> MddResult<Value> {
    let path = std::env::args_os().nth(1).map(PathBuf::from).ok_or_else(|| {
        MddError::new(ErrorCode::InvalidArgument, "annotation_order_probe", "missing fixture")
    })?;
    let specs = (0..2).map(|_| InputSpec {
        path:path.clone(), kind:InputKind::RawDex, expected_sha256:None,
    }).collect::<Vec<_>>();
    let snapshot = Snapshot::capture(&specs, CaptureLimits::default())?;
    let inventories = snapshot.sources().iter().map(|source| {
        ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
    }).collect::<MddResult<Vec<_>>>()?;
    let scope = SelectedScope::from_inventories(&snapshot, &inventories.iter().collect::<Vec<_>>())?;
    if scope.dexes().len() != 2 || !scope.roster_complete() || !scope.covers_all_captured_sources() {
        return Err(MddError::new(ErrorCode::IncompleteFacts, "annotation_order_probe", "incomplete source roster"));
    }
    let mut occurrences = Vec::new();
    for (index, inventory) in inventories.iter().enumerate() {
        let metadata = MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default())?;
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
        let facts = AnnotationFacts::build(definitions, AnnotationLimits::default())?;
        let selected = &scope.dexes()[index];
        if selected.dex_occurrence_id != facts.source().dex_occurrence_id {
            return Err(MddError::new(ErrorCode::InternalFault, "annotation_order_probe", "source binding mismatch"));
        }
        let id = selected.file_id;
        occurrences.push(json!({"selected":selected, "source":facts.source(),
            "annotation_coverage":facts.annotation_coverage(),
            "prototype_positions_error":facts.require_complete_parameter_positions().err(),
            "rows":{"annotation_directory_entries":facts.directory_entry_rows(id),
                    "annotation_set_entries":facts.set_entry_rows(id),
                    "annotations":facts.annotation_rows(id), "annotation_elements":facts.element_rows(id)}}));
    }
    Ok(json!({"operation_status":"ok", "probe_complete":true, "occurrences":occurrences,
              "snapshot_id":scope.snapshot_id(), "scope_id":scope.scope_id(), "profile_admitted":false}))
}
fn main() -> ExitCode {
    match run() {
        Ok(value) => { println!("{value}"); ExitCode::SUCCESS }
        Err(error) => { eprintln!("{error:?}"); ExitCode::FAILURE }
    }
}
