//! Emit real metadata facts for two distinct occurrences of the same raw DEX.
use mdd_dex::strings::StringLimits;
use mdd_facts::{MetadataFacts, indexes::SelectedScope};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{path::PathBuf, process::ExitCode};

fn run() -> MddResult<Value> {
    let path = std::env::args_os().nth(1).map(PathBuf::from).ok_or_else(|| {
        MddError::new(ErrorCode::InvalidArgument, "header_probe", "missing input")
    })?;
    let specs = (0..2).map(|_| InputSpec {
        path: path.clone(), kind: InputKind::RawDex, expected_sha256: None,
    }).collect::<Vec<_>>();
    let snapshot = Snapshot::capture(&specs, CaptureLimits::default())?;
    let inventories = snapshot.sources().iter().map(|source| {
        ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
    }).collect::<MddResult<Vec<_>>>()?;
    let scope = SelectedScope::from_inventories(&snapshot, &inventories.iter().collect::<Vec<_>>())?;
    if scope.dexes().len() != 2 || !scope.roster_complete() || !scope.covers_all_captured_sources() {
        return Err(MddError::new(ErrorCode::IncompleteFacts, "header_probe", "input roster incomplete"));
    }
    let mut occurrences = Vec::new();
    for (index, inventory) in inventories.iter().enumerate() {
        let facts = MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default())?;
        let selected = &scope.dexes()[index];
        if selected.dex_occurrence_id != facts.source().dex_occurrence_id {
            return Err(MddError::new(ErrorCode::InternalFault, "header_probe", "occurrence binding mismatch"));
        }
        occurrences.push(json!({"selected":selected, "source":facts.source(),
            "byte_len":facts.bytes().len(), "header":facts.header(), "string_pool":facts.string_pool()}));
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
