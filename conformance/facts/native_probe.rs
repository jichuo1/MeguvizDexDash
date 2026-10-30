//! Conformance-only composition of public fact APIs. This is not a production
//! relation provider, coverage signer, query executor, or fallback.
use mdd_dex::{
    annotations::AnnotationLimits, definitions::DefinitionLimits, instructions::CodeLimits,
    strings::StringLimits,
};
use mdd_facts::{
    MetadataFacts,
    annotations::AnnotationFacts,
    code::CodeFacts,
    definitions::{DefinitionFacts, DefinitionRelation},
    raw_fingerprints::{FingerprintLimits, RawCodeEvidence},
    references::{ReferenceFacts, ReferenceLimits, TargetKind},
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf, process::ExitCode};

fn require(ok: bool, message: &str) -> MddResult<()> {
    if ok {
        Ok(())
    } else {
        Err(MddError::new(
            ErrorCode::InternalFault,
            "conformance.facts",
            message,
        ))
    }
}
fn run() -> MddResult<Value> {
    let paths: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    require(
        !paths.is_empty() && paths.len() <= 8,
        "tiny probe needs 1..8 raw DEX inputs",
    )?;
    for path in &paths {
        let size = std::fs::metadata(path)
            .map_err(|e| {
                MddError::new(ErrorCode::InvalidInput, "conformance.facts", e.to_string())
            })?
            .len();
        require(
            size <= 1024 * 1024,
            "tiny conformance probe refuses an input above 1MiB",
        )?;
    }
    let specs: Vec<_> = paths
        .into_iter()
        .map(|path| InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        })
        .collect();
    let snapshot = Snapshot::capture(&specs, CaptureLimits::default())?;
    let mut results = Vec::new();
    let mut held = Vec::new();
    for source in snapshot.sources() {
        let inventory =
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())?;
        for index in 0..inventory.selected_dexes().len() {
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, index, StringLimits::default())?;
            let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
            let metadata_json = json!(definitions.metadata());
            let definitions_json = json!(definitions.definitions());
            let annotations = match AnnotationFacts::build(
                definitions.clone(),
                AnnotationLimits::default(),
            ) {
                Ok(facts) => {
                    json!({"operation_status":"ok", "source":facts.source(), "facts":facts.data(),
                    "signatures":facts.signatures(), "coverage":facts.annotation_coverage(),
                    "prototype_positions_gate":facts.require_complete_parameter_positions().err(),
                    "rows":{"annotation_directory_entries":facts.directory_entry_rows(0),
                        "annotation_set_entries":facts.set_entry_rows(0), "annotations":facts.annotation_rows(0),
                        "annotation_elements":facts.element_rows(0)}})
                }
                Err(error) => json!({"operation_status":"error", "error":error}),
            };
            let code = CodeFacts::build_all_code_items(
                &snapshot,
                &inventory,
                index,
                CodeLimits::default(),
            )?;
            let code_json = json!(code);
            let raw = RawCodeEvidence::build(&definitions, &code, FingerprintLimits::default())?;
            let method_columns = ["opcode_count", "opcode_hex", "param_descriptors", "*"]
                .into_iter()
                .map(|name| {
                    (
                        name.to_owned(),
                        json!(
                            definitions
                                .require_relation_columns(DefinitionRelation::Methods, &[name])
                                .err()
                        ),
                    )
                })
                .collect::<serde_json::Map<_, _>>();
            let references = ReferenceFacts::build(definitions, code, ReferenceLimits::default())?;
            let mut targets = BTreeSet::new();
            for site in references.sites() {
                targets.insert((site.target_kind, site.target_local_index));
            }
            for (kind, len) in [
                (
                    TargetKind::String,
                    references.definitions().metadata().strings().len(),
                ),
                (
                    TargetKind::Type,
                    references.definitions().metadata().types().len(),
                ),
                (
                    TargetKind::Method,
                    references
                        .definitions()
                        .definitions()
                        .method_references
                        .len(),
                ),
                (
                    TargetKind::Field,
                    references
                        .definitions()
                        .definitions()
                        .field_references
                        .len(),
                ),
                (
                    TargetKind::Prototype,
                    references.definitions().metadata().prototypes().len(),
                ),
            ] {
                for index in 0..len {
                    targets.insert((kind, index as u32));
                }
            }
            let mut checked = 0;
            for (kind, index) in targets {
                let target = references.target_id(kind, index)?;
                require(
                    references.find_target_indexed(&target)?
                        == references.find_target_scalar(&target)?,
                    "indexed/scalar reference target mismatch",
                )?;
                checked += 1;
            }
            let strings = references
                .method_string_rows(0)
                .map(|rows| json!({"operation_status":"ok", "rows":rows}))
                .unwrap_or_else(|error| json!({"operation_status":"error", "error":error}));
            results.push(json!({"source":references.source(), "metadata":metadata_json,
                "definitions":definitions_json, "annotations":annotations, "code":code_json,
                "raw_code_evidence":raw,"method_column_gates":method_columns,
                "references":{"coverage":references.coverage(), "sites":references.sites(), "dynamic_calls":references.dynamic_calls(),
                    "indexed_scalar_target_checks":checked,"method_strings":strings,
                    "method_calls":references.method_call_rows(0)?,"method_field_accesses":references.method_field_rows(0)?,
                    "method_used_types":references.method_type_rows(0)?},
                "conformance_file_id":0,"file_id_policy":"per-occurrence rows intentionally use explicit 0; no production catalog assignment claimed"}));
            held.push(references);
        }
    }
    let mut foreign_checks = Vec::new();
    if held.len() > 1 {
        for index in 1..held.len() {
            let target = held[0].target_id(TargetKind::String, 0)?;
            let error = held[index]
                .find_target_indexed(&target)
                .expect_err("foreign occurrence target must be rejected");
            require(
                error.code == ErrorCode::InvalidArgument,
                "foreign target rejected with unexpected code",
            )?;
            require(
                held[0].source().dex_occurrence_id != held[index].source().dex_occurrence_id,
                "duplicate occurrence identity collapsed",
            )?;
            foreign_checks.push(json!({"target_source":held[0].source().dex_occurrence_id,
                "lookup_source":held[index].source().dex_occurrence_id,"error":error}));
        }
    }
    Ok(
        json!({"probe":"conformance-only-public-fact-composition-v1", "operation_status":"ok", "snapshot":snapshot.manifest(),
        "dex_occurrences":results,"foreign_occurrence_checks":foreign_checks,"probe_complete":true,
        "fact_coverage_signer_implemented":false,"production_complete_audit":false}),
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
                json!({"operation_status":"error","error":error,"probe_complete":false})
            );
            ExitCode::FAILURE
        }
    }
}
