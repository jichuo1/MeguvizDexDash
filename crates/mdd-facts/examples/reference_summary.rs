//! Self-owned reference consumer. Full tiny relations are explicit and bounded.
use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits};
use mdd_facts::{
    MetadataFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    references::{
        DefinitionSearchLimits, DefinitionWorld, ReferenceFacts, ReferenceLimits, TargetKind,
    },
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{Completeness, ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf, process::ExitCode};

fn run() -> MddResult<Value> {
    let mut arguments = std::env::args_os().skip(1);
    let path = arguments.next().map(PathBuf::from).ok_or_else(|| {
        MddError::new(
            ErrorCode::InvalidArgument,
            "example",
            "usage: reference_summary INPUT [EXPECTED_SHA256] [--relations]",
        )
    })?;
    let mut expected = None;
    let mut relations = false;
    for argument in arguments {
        if argument == "--relations" {
            relations = true;
        } else if expected.is_none() {
            expected = Some(argument.into_string().map_err(|_| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "example",
                    "expected digest is not text",
                )
            })?);
        } else {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "example",
                "unexpected argument",
            ));
        }
    }
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
            expected_sha256: expected,
        }],
        CaptureLimits::default(),
    )?;
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )?;
    let mut facts = Vec::new();
    for index in 0..inventory.selected_dexes().len() {
        let metadata = MetadataFacts::build(&snapshot, &inventory, index, StringLimits::default())?;
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
        let code =
            CodeFacts::build_all_code_items(&snapshot, &inventory, index, CodeLimits::default())?;
        facts.push(ReferenceFacts::build(
            definitions,
            code,
            ReferenceLimits::default(),
        )?);
    }
    let definition_refs = facts
        .iter()
        .map(ReferenceFacts::definitions)
        .collect::<Vec<_>>();
    let world = DefinitionWorld::from_complete_selected_inputs(
        &snapshot,
        &[&inventory],
        &definition_refs,
        DefinitionSearchLimits::default(),
    )?;
    let mut summaries = Vec::new();
    let mut all_relations = Vec::new();
    for (index, fact) in facts.iter().enumerate() {
        let strings = fact
            .sites()
            .iter()
            .filter(|site| site.target_kind == TargetKind::String)
            .map(|site| site.target_local_index)
            .collect::<BTreeSet<_>>();
        let non_scalar = strings
            .iter()
            .filter(|index| {
                fact.definitions().metadata().strings()[**index as usize]
                    .data
                    .text
                    .strict_utf8()
                    .is_err()
            })
            .count();
        let count = |kind| {
            fact.sites()
                .iter()
                .filter(|site| site.target_kind == kind)
                .count()
        };
        summaries.push(json!({"dex_occurrence_id":fact.source().dex_occurrence_id,"content_id":fact.source().content_id,"coverage":fact.coverage(),"usage":fact.usage(),
            "site_count":fact.sites().len(),"method_string_sites":count(TargetKind::String),"encoded_method_reference_sites":count(TargetKind::Method),"method_field_access_sites":count(TargetKind::Field),"method_used_type_sites":count(TargetKind::Type),
            "prototype_sites":count(TargetKind::Prototype),"method_handle_sites":count(TargetKind::MethodHandle),"custom_call_sites":fact.dynamic_calls().len(),
            "non_scalar_referenced_strings":non_scalar,"plain_utf8_projection":if non_scalar==0{"available_losslessly"}else{"unsupported_query; raw UTF16 reference facts retained"},
            "reference_calculation_complete":fact.coverage().facts==Completeness::Complete,"runtime_targets_inferred":false,"full_audit_complete":false,
            "code_projection_scope":fact.code().scope(),"call_site_metadata_scope":fact.call_site_metadata().map(|section|section.validated_scope.as_str())}));
        if relations {
            if fact.sites().len() > 1000 {
                return Err(MddError::new(
                    ErrorCode::QuotaExceeded,
                    "example",
                    "full reference relation output restricted to tiny fixtures",
                ));
            }
            let strings = match fact.method_string_rows(index as u32) {
                Ok(rows) => json!({"operation_status":"ok","rows":rows}),
                Err(error) => json!({"operation_status":"error","error":error}),
            };
            let sites = (0..fact.sites().len())
                .map(|ordinal| fact.scoped_site(ordinal as u32))
                .collect::<MddResult<Vec<_>>>()?;
            all_relations.push(json!({"file_id":index,"method_strings":strings,"method_calls":fact.method_call_rows(index as u32)?,"method_field_accesses":fact.method_field_rows(index as u32)?,"method_used_types":fact.method_type_rows(index as u32)?,"sites":sites,"dynamic_calls":fact.dynamic_calls(),"method_handles":fact.method_handle_metadata()}));
        }
    }
    Ok(
        json!({"operation_status":"ok","engine":"MeguvizDexDash","scope":"encoded-reference-sites-in-defined-methods-v1","snapshot_id":snapshot.manifest().snapshot_id,"input_content_id":snapshot.manifest().sources[0].content_id,"captured_input_bytes":snapshot.manifest().captured_input_bytes,
        "selected_dexes":summaries,"definition_search_scope":world.scope(),"relations":if relations{Some(all_relations)}else{None},"reference_calculation_complete":facts.iter().all(|fact|fact.coverage().facts==Completeness::Complete),"full_dex_validation_complete":false,"full_audit_complete":false,
        "qualification":"self-owned complete encoded reference construction only; no runtime call graph, HostLab profile or performance qualification"}),
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
                json!({"operation_status":"error","error":error,"full_audit_complete":false})
            );
            ExitCode::FAILURE
        }
    }
}
