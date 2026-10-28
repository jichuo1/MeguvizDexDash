//! Complete physical code-map consumption with summary output, never an audit.
use mdd_dex::instructions::CodeLimits;
use mdd_facts::code::CodeFacts;
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use std::{collections::BTreeSet, path::PathBuf, process::ExitCode};

fn run() -> MddResult<serde_json::Value> {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(args.next().ok_or_else(|| {
        MddError::new(
            ErrorCode::InvalidArgument,
            "example",
            "usage: code_layout_summary INPUT [EXPECTED_SHA256]",
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
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dex"))
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
    for index in 0..inventory.selected_dexes().len() {
        let facts =
            CodeFacts::build_all_code_items(&snapshot, &inventory, index, CodeLimits::default())?;
        let mut instructions = 0u64;
        let mut units = 0u64;
        let mut payloads = 0u64;
        let mut tries = 0u64;
        let mut debug_events = 0u64;
        let mut positions_without_source_line = 0u64;
        let mut debug_programs = BTreeSet::new();
        for fact in facts.items() {
            instructions += fact.data().instructions.len() as u64;
            units += u64::from(fact.data().insns_size_code_units);
            payloads += fact.data().payloads.len() as u64;
            tries += fact.data().tries.len() as u64;
            if let Some(debug) = &fact.data().debug_info {
                debug_events += debug.events.len() as u64;
                positions_without_source_line += debug
                    .events
                    .iter()
                    .filter(|event| event.emits_position && !event.source_line_usable)
                    .count() as u64;
                debug_programs.insert(debug.raw_range.byte_offset.0);
            }
        }
        rows.push(serde_json::json!({"source":facts.source(),"scope":facts.scope(),
            "declared_map_code_items":facts.declared_map_code_item_count(),
            "consumed_code_items":DecimalU64(facts.items().len() as u64),
            "instructions":DecimalU64(instructions),"code_units":DecimalU64(units),
            "payloads":DecimalU64(payloads),"try_ranges":DecimalU64(tries),
            "unique_debug_programs":DecimalU64(debug_programs.len() as u64),
            "debug_events_materialized":DecimalU64(debug_events),
            "emitted_positions_without_source_line":DecimalU64(positions_without_source_line),
            "debug_policy":facts.debug_policy(),"source_positions_built":facts.source_positions_built(),
            "coverage":facts.code_layout_coverage(),"method_ownership_built":facts.method_ownership_built(),
            "references_built":facts.references_built(),"full_dex_validation_complete":facts.full_dex_validation_complete()}));
    }
    Ok(
        serde_json::json!({"operation_status":"ok","input_content_id":snapshot.manifest().sources[0].content_id,
        "required_dex_occurrences":inventory.selected_dexes().len(),"selected_dexes":rows,
        "calculation_complete":true,"full_audit_complete":false,
        "scope":"all physical code-map items; summary after complete calculation; no ART type-flow or performance qualification"}),
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
