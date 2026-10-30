//! Complete raw evidence calculation with bounded summary output.
use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits};
use mdd_facts::{
    MetadataFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    raw_fingerprints::{FingerprintLimits, RawCodeEvidence, ResourceByteEvidence},
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult, sha256};
use std::{path::PathBuf, process::ExitCode};

fn run() -> MddResult<serde_json::Value> {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(args.next().ok_or_else(|| {
        MddError::new(
            ErrorCode::InvalidArgument,
            "example",
            "usage: raw_evidence_summary APK [EXPECTED_SHA256]",
        )
    })?);
    let expected_sha256 = args
        .next()
        .map(|value| {
            value.into_string().map_err(|_| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "example",
                    "expected SHA-256 is not ASCII",
                )
            })
        })
        .transpose()?;
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path,
            kind: InputKind::Apk,
            expected_sha256,
        }],
        CaptureLimits::default(),
    )?;
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )?;
    let mut dexes = Vec::new();
    for index in 0..inventory.selected_dexes().len() {
        let metadata = MetadataFacts::build(&snapshot, &inventory, index, StringLimits::default())?;
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
        let code =
            CodeFacts::build_all_code_items(&snapshot, &inventory, index, CodeLimits::default())?;
        let raw = RawCodeEvidence::build(&definitions, &code, FingerprintLimits::default())?;
        let mut records:Vec<_>=raw.methods().iter().map(|method|serde_json::json!({
            "method_idx":method.method.local_index,"body_kind":method.body_kind,
            "insns_off":method.insns_range.as_ref().map(|range|range.byte_offset),
            "insns_size":method.insns_range.as_ref().map(|range|(range.byte_length.0/2).to_string()),
            "sha256":method.sha256})).collect();
        records.sort_by_key(|record| record["method_idx"].as_u64().unwrap());
        let canonical = serde_json::to_vec(&records).map_err(|failure| {
            MddError::new(ErrorCode::InternalFault, "example", failure.to_string())
        })?;
        // This diagnostic consumer implements the retained HostLab ordering;
        // the generic evidence API only hashes caller-ordered byte chunks.
        let mut class_digests = Vec::new();
        for class in &definitions.definitions().classes {
            let mut entries = Vec::new();
            for method in definitions
                .definitions()
                .method_definitions
                .iter()
                .filter(|method| method.class_def_idx == class.class_def_idx)
            {
                let reference =
                    &definitions.definitions().method_references[method.method_idx as usize];
                let prototype =
                    &definitions.metadata().prototypes()[reference.proto_idx as usize].data;
                let spaced = format!(
                    "({}){}",
                    reference.parameter_descriptors.join(" "),
                    reference.return_descriptor
                );
                entries.push((
                    (reference.method_name.clone(), spaced),
                    method.method_idx,
                    format!("{}{}", reference.method_name, prototype.descriptor).into_bytes(),
                ));
            }
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let entities: Vec<_> = entries
                .iter()
                .map(|entry| definitions.entity(mdd_facts::EntityKind::MethodDefinition, entry.1))
                .collect::<MddResult<_>>()?;
            let parts: Vec<_> = entities
                .iter()
                .zip(&entries)
                .map(|(entity, entry)| (entity, entry.2.as_slice()))
                .collect();
            class_digests.push(serde_json::json!({"class_def_idx":class.class_def_idx,"descriptor":class.descriptor,
                "method_bodies_sha256":raw.ordered_digest(&parts,u64::MAX)?}));
        }
        let class_canonical = serde_json::to_vec(&class_digests).map_err(|failure| {
            MddError::new(ErrorCode::InternalFault, "example", failure.to_string())
        })?;
        dexes.push(serde_json::json!({"member_id":raw.source().member_id,"content_id":raw.source().content_id,
            "method_count":records.len(),"canonical_method_evidence_sha256":sha256(&canonical),
            "class_count":class_digests.len(),"legacy_class_recipe_sha256":sha256(&class_canonical),
            "canonical_contract":"sorted method_idx; JSON object keys sorted; UTF8 compact; off/size decimal strings; no-body null"}));
    }
    let mut resources = serde_json::Map::new();
    for member in &inventory.manifest().members {
        let raw = &member.raw_name;
        if raw == b"resources.arsc" || (raw.starts_with(b"res/") && raw.ends_with(b".xml")) {
            let name = member.name_utf8.as_ref().ok_or_else(|| {
                MddError::new(
                    ErrorCode::UnsupportedQuery,
                    "example",
                    "plain resource-name projection requires scalar UTF8",
                )
            })?;
            if resources.contains_key(name) {
                return Err(MddError::new(
                    ErrorCode::AmbiguousEntity,
                    "example",
                    "name-keyed diagnostic cannot collapse duplicate physical resources",
                ));
            }
            let evidence = ResourceByteEvidence::build(&snapshot, &inventory, &member.member_id)?;
            resources.insert(
                name.clone(),
                serde_json::Value::String(evidence.sha256().to_owned()),
            );
        }
    }
    Ok(
        serde_json::json!({"operation_status":"ok","input_content_id":snapshot.manifest().sources[0].content_id,
        "selected_dexes":dexes,"resource_fingerprints":resources,"calculation_complete":true,"full_audit_complete":false,
        "scope":"exact raw insns and explicitly selected Android resource bytes; no source/ART/HostLab/performance qualification"}),
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
