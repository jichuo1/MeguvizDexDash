//! Full definition metadata consumption; code and annotations remain separate.
use mdd_dex::{
    definitions::{DefinitionLimits, MethodBody},
    strings::StringLimits,
};
use mdd_facts::{MetadataFacts, definitions::DefinitionFacts};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use std::{path::PathBuf, process::ExitCode};

fn run() -> MddResult<serde_json::Value> {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(args.next().ok_or_else(|| {
        MddError::new(
            ErrorCode::InvalidArgument,
            "example",
            "usage: definition_summary INPUT [EXPECTED_SHA256]",
        )
    })?);
    let expected_sha256 = args
        .next()
        .map(|value| {
            value.into_string().map_err(|_| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "example",
                    "expected SHA-256 must be ASCII",
                )
            })
        })
        .transpose()?;
    let kind = if path
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case("dex"))
    {
        InputKind::RawDex
    } else {
        InputKind::Apk
    };
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path,
            kind,
            expected_sha256,
        }],
        CaptureLimits::default(),
    )?;
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )?;
    let mut rows = Vec::new();
    for dex_index in 0..inventory.selected_dexes().len() {
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, dex_index, StringLimits::default())?;
        let facts = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
        let mut absent_native = 0u64;
        let mut absent_abstract = 0u64;
        let mut declared_present = 0u64;
        for method in &facts.definitions().method_definitions {
            match method.body {
                MethodBody::Native => absent_native += 1,
                MethodBody::Abstract => absent_abstract += 1,
                MethodBody::Present { .. } => declared_present += 1,
            }
        }
        rows.push(serde_json::json!({"source":facts.metadata().source(),
            "classes":DecimalU64(facts.definitions().classes.len() as u64),
            "interfaces":DecimalU64(facts.definitions().interfaces.len() as u64),
            "field_references":DecimalU64(facts.definitions().field_references.len() as u64),
            "field_definitions":DecimalU64(facts.definitions().field_definitions.len() as u64),
            "method_references":DecimalU64(facts.definitions().method_references.len() as u64),
            "method_definitions":DecimalU64(facts.definitions().method_definitions.len() as u64),
            "no_body_native":DecimalU64(absent_native),"no_body_abstract":DecimalU64(absent_abstract),
            "declared_present_bodies":DecimalU64(declared_present),
            "definition_coverage":facts.definition_coverage(),"unbuilt_layers":facts.unbuilt_layers()}));
    }
    Ok(
        serde_json::json!({"operation_status":"ok","input_content_id":snapshot.manifest().sources[0].content_id,
        "required_dex_occurrences":inventory.selected_dexes().len(),"selected_dexes":rows,
        "calculation_complete":true,"full_audit_complete":false,
        "scope":"complete encoded definition metadata only; body offsets do not claim built code-layout/annotations/references"}),
    )
}

fn main() -> ExitCode {
    match run() {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"operation_status":"error","error":error,"calculation_complete":false,"full_audit_complete":false})
            );
            ExitCode::FAILURE
        }
    }
}
