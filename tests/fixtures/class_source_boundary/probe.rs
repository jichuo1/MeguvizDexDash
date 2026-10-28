//! Observe source-bound class facts and explicit strict-text conversion outcomes.
use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
use mdd_facts::{MetadataFacts, definitions::DefinitionFacts, indexes::SelectedScope};
use mdd_input::{archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
                snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot}};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{path::PathBuf, process::ExitCode};

fn run() -> MddResult<Value> {
    let paths = std::env::args_os().skip(1).map(PathBuf::from).collect::<Vec<_>>();
    if paths.is_empty() || paths.len() > 4 {
        return Err(MddError::new(ErrorCode::InvalidArgument,"class_source_probe","expected one to four inputs"));
    }
    let specs = paths.into_iter().map(|path|InputSpec { path,kind:InputKind::RawDex,expected_sha256:None }).collect::<Vec<_>>();
    let snapshot = Snapshot::capture(&specs,CaptureLimits::default())?;
    let inventories = snapshot.sources().iter().map(|source| {
        ArchiveInventory::build(source,InventoryPolicy::default(),ArchiveLimits::default())
    }).collect::<MddResult<Vec<_>>>()?;
    let scope = SelectedScope::from_inventories(&snapshot,&inventories.iter().collect::<Vec<_>>())?;
    let mut output = Vec::new();
    for (index, inventory) in inventories.iter().enumerate() {
        let metadata = MetadataFacts::build(&snapshot,inventory,0,StringLimits::default())?;
        let facts = DefinitionFacts::build(metadata,DefinitionLimits::default())?;
        let selected = scope.dexes().get(index).ok_or_else(||MddError::new(ErrorCode::IncompleteFacts,"class_source_probe","missing DEX occurrence"))?;
        if selected.dex_occurrence_id != facts.metadata().source().dex_occurrence_id {
            return Err(MddError::new(ErrorCode::InternalFault,"class_source_probe","source identity mismatch"));
        }
        let classes = facts.definitions().classes.iter().map(|class| {
            let strict = match &class.source_file {
                None => json!({"status":"absent"}),
                Some(text) => match text.strict_utf8() {
                    Ok(value) => json!({"status":"scalar","value":value}),
                    Err(_) => json!({"status":"non_scalar"}),
                },
            };
            json!({"fact":class,"source_file_strict":strict})
        }).collect::<Vec<_>>();
        output.push(json!({"selected":selected,"source":facts.metadata().source(),"classes":classes}));
    }
    Ok(json!({"operation_status":"ok","probe_complete":true,"occurrences":output,
              "snapshot_id":scope.snapshot_id(),"scope_id":scope.scope_id(),"profile_admitted":false}))
}
fn main() -> ExitCode {
    match run() {
        Ok(value) => { println!("{value}"); ExitCode::SUCCESS }
        Err(error) => { println!("{}",json!({"operation_status":"error","error":error,"probe_complete":false})); ExitCode::FAILURE }
    }
}
