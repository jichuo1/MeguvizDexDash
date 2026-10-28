//! Real annotation API consumer; full relations are restricted to tiny fixtures.
use mdd_dex::{
    annotations::{AnnotationLimits, AnnotationOwnerKind},
    definitions::DefinitionLimits,
    strings::StringLimits,
};
use mdd_facts::{MetadataFacts, annotations::AnnotationFacts, definitions::DefinitionFacts};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{path::PathBuf, process::ExitCode};

fn run() -> MddResult<Value> {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().map(PathBuf::from).ok_or_else(|| {
        MddError::new(
            ErrorCode::InvalidArgument,
            "example",
            "usage: annotation_summary INPUT [EXPECTED_SHA256] [--relations]",
        )
    })?;
    let mut expected_sha256 = None;
    let mut relations = false;
    for argument in args {
        if argument == "--relations" {
            relations = true;
        } else if expected_sha256.is_none() {
            expected_sha256 = Some(argument.into_string().map_err(|_| {
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
            expected_sha256,
        }],
        CaptureLimits::default(),
    )?;
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )?;
    let mut summaries = Vec::new();
    let mut tiny_relations = Vec::new();
    for index in 0..inventory.selected_dexes().len() {
        let metadata = MetadataFacts::build(&snapshot, &inventory, index, StringLimits::default())?;
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
        let facts = AnnotationFacts::build(definitions, AnnotationLimits::default())?;
        let data = facts.data();
        let mut shorter_lists = 0;
        let mut longer_lists = 0;
        for binding in &data.directory_bindings {
            let directory = data
                .directories
                .iter()
                .find(|item| item.byte_offset == binding.directory_byte_offset)
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "example",
                        "validated directory binding missing",
                    )
                })?;
            for entry in &directory.entries {
                if entry.kind != AnnotationOwnerKind::Parameter {
                    continue;
                }
                let method = &facts.definitions().definitions().method_references
                    [entry.local_index as usize];
                let count = facts.definitions().metadata().prototypes()[method.proto_idx as usize]
                    .data
                    .parameter_type_indices
                    .len();
                let list = data
                    .ref_lists
                    .iter()
                    .find(|item| item.byte_offset == entry.target_byte_offset)
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "example",
                            "validated parameter ref-list missing",
                        )
                    })?;
                shorter_lists += usize::from(list.annotation_set_offsets.len() < count);
                longer_lists += usize::from(list.annotation_set_offsets.len() > count);
            }
        }
        summaries.push(json!({
            "dex_occurrence_id":facts.source().dex_occurrence_id,"content_id":facts.source().content_id,
            "version":facts.definitions().metadata().header().version,
            "physical_annotation_items":data.annotation_items.len(),"physical_encoded_arrays":data.encoded_arrays.len(),
            "validated_call_site_prefixes":data.call_site_arrays.len(),
            "physical_annotation_sets":data.sets.len(),"physical_ref_lists":data.ref_lists.len(),"physical_directories":data.directories.len(),
            "class_directory_bindings":data.directory_bindings.len(),"owner_bindings":data.owner_bindings.len(),"value_nodes":data.values.len(),
            "signature_facts":facts.signatures().len(),"signature_parts":facts.signatures().iter().map(|item|item.parts.len()).sum::<usize>(),
            "signature_utf16_units":facts.signatures().iter().map(|item|item.utf16_units.len()).sum::<usize>(),
            "signatures_without_scalar_utf8":facts.signatures().iter().filter(|item|item.strict_utf8().is_err()).count(),
            "encoded_parameter_slots":data.owner_bindings.iter().filter(|owner|owner.kind==AnnotationOwnerKind::Parameter).count(),
            "explicit_null_parameter_slots":data.owner_bindings.iter().filter(|owner|owner.kind==AnnotationOwnerKind::Parameter&&owner.annotation_set_offset.is_none()).count(),
            "parameter_lists_shorter_than_prototype":shorter_lists,"parameter_lists_longer_than_prototype":longer_lists,
            "prototype_parameter_position_coverage":if facts.require_complete_parameter_positions().is_ok(){"complete"}else{"unknown"},
            "completed_layers":facts.completed_layers(),"unbuilt_layers":facts.unbuilt_layers(),"usage":data.usage,
            "annotation_calculation_complete":true,"parameter_slot_scope":"exact encoded slots only; absent slots are not manufactured NULL rows",
            "full_dex_validation_complete":false,"full_audit_complete":false
        }));
        if relations {
            if data.values.len() > 10000 || data.owner_bindings.len() > 10000 {
                return Err(MddError::new(
                    ErrorCode::QuotaExceeded,
                    "example",
                    "full relation output is restricted to tiny fixtures",
                ));
            }
            tiny_relations.push(json!({"file_id":index,"annotation_directories":facts.directory_rows(index as u32),"annotation_directory_entries":facts.directory_entry_rows(index as u32),
                "annotation_set_entries":facts.set_entry_rows(index as u32),"annotation_set_refs":facts.set_ref_rows(index as u32),"annotations":facts.annotation_rows(index as u32),"annotation_elements":facts.element_rows(index as u32),
                "signatures":facts.signatures(),"physical_encoded_arrays":data.encoded_arrays,"physical_directories":data.directories,"call_site_array_bindings":data.call_site_arrays}));
        }
    }
    Ok(
        json!({"operation_status":"ok","engine":"MeguvizDexDash","scope":"physical-annotations-encoded-values-signature-fragments-v1","snapshot_id":snapshot.manifest().snapshot_id,
        "input_content_id":snapshot.manifest().sources[0].content_id,"captured_input_bytes":snapshot.manifest().captured_input_bytes,"selected_dexes":summaries,
        "relations":if relations{Some(tiny_relations)}else{None},"annotation_calculation_complete":true,"full_audit_complete":false,
        "qualification":"actual self-owned reader construction only; not a HostLab or performance compatibility qualification"}),
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
