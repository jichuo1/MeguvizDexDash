//! Capture source occurrences, archive members, physical pools and string facts.
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
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.len() % 2 != 0 || args.len() > 8 {
        return Err(MddError::new(ErrorCode::InvalidArgument, "cross_dex_probe", "need 1..4 kind/path pairs"));
    }
    let mut inputs = Vec::new();
    for pair in args.chunks_exact(2) {
        let kind = match pair[0].to_str() {
            Some("dex") => InputKind::RawDex,
            Some("apk") => InputKind::Apk,
            _ => return Err(MddError::new(ErrorCode::InvalidArgument, "cross_dex_probe", "invalid input kind")),
        };
        inputs.push(InputSpec { path:PathBuf::from(&pair[1]), kind, expected_sha256:None });
    }
    let snapshot = Snapshot::capture(&inputs, CaptureLimits::default())?;
    let inventories = snapshot.sources().iter().map(|source| {
        ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
    }).collect::<MddResult<Vec<_>>>()?;
    let scope = SelectedScope::from_inventories(&snapshot, &inventories.iter().collect::<Vec<_>>())?;
    if !scope.roster_complete() || !scope.covers_all_captured_sources() {
        return Err(MddError::new(ErrorCode::IncompleteFacts, "cross_dex_probe", "incomplete roster"));
    }
    let mut output = Vec::new();
    let mut scope_index = 0;
    for inventory in &inventories {
        for (index, dex) in inventory.selected_dexes().iter().enumerate() {
            let metadata = MetadataFacts::build(&snapshot, inventory, index, StringLimits::default())?;
            let selected = scope.dexes().get(scope_index).ok_or_else(|| {
                MddError::new(ErrorCode::InternalFault, "cross_dex_probe", "selected DEX missing")
            })?;
            if selected.dex_occurrence_id != metadata.source().dex_occurrence_id {
                return Err(MddError::new(ErrorCode::InternalFault, "cross_dex_probe", "occurrence mismatch"));
            }
            output.push(json!({"selected":selected, "source":metadata.source(), "member":dex.blob.identity,
                               "pool":metadata.string_pool(), "strings":metadata.strings()}));
            scope_index += 1;
        }
    }
    if scope_index != scope.dexes().len() {
        return Err(MddError::new(ErrorCode::InternalFault, "cross_dex_probe", "extra selected DEX"));
    }
    Ok(json!({"operation_status":"ok", "probe_complete":true, "snapshot_id":scope.snapshot_id(),
              "scope_id":scope.scope_id(), "inputs":scope.inputs(), "occurrences":output,
              "profile_admitted":false}))
}

fn main() -> ExitCode {
    match run() {
        Ok(value) => { println!("{value}"); ExitCode::SUCCESS }
        Err(error) => { eprintln!("{error:?}"); ExitCode::FAILURE }
    }
}
