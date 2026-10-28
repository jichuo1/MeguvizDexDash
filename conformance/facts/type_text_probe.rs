//! Expose real lossless metadata and strict scalar conversion outcomes.
use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
                snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot}};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{path::PathBuf, process::ExitCode};

fn run() -> MddResult<Value> {
    let path = std::env::args_os().nth(1).map(PathBuf::from).ok_or_else(|| {
        MddError::new(ErrorCode::InvalidArgument, "type_text_probe", "missing fixture")
    })?;
    let snapshot = Snapshot::capture(&[InputSpec { path, kind:InputKind::RawDex, expected_sha256:None }],
                                     CaptureLimits::default())?;
    let inventory = ArchiveInventory::build(&snapshot.sources()[0], InventoryPolicy::default(), ArchiveLimits::default())?;
    let facts = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default())?;
    let strings = facts.strings().iter().map(|fact| {
        let strict = match fact.data.text.strict_utf8() {
            Ok(value) => json!({"status":"scalar", "value":value}),
            Err(_) => json!({"status":"non_scalar"}),
        };
        json!({"fact":fact, "strict_utf8":strict})
    }).collect::<Vec<_>>();
    Ok(json!({"operation_status":"ok", "probe_complete":true, "source":facts.source(),
              "pool":facts.string_pool(), "types":facts.types(), "strings":strings, "profile_admitted":false}))
}

fn main() -> ExitCode {
    match run() {
        Ok(value) => { println!("{value}"); ExitCode::SUCCESS }
        Err(error) => { println!("{}", json!({"operation_status":"error", "error":error})); ExitCode::FAILURE }
    }
}
