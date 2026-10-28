//! Immutable source-bound annotation relations and ordered Signature fragments.
use crate::{
    definitions::DefinitionFacts,
    metadata::{EntityKind, EntityRef, MetadataSource},
};
use mdd_dex::annotations::{
    AnnotationLimits, AnnotationOwnerBinding, AnnotationOwnerKind, DexAnnotations, EncodedKind,
    ExactFloat, read_annotations,
};
use mdd_types::{Completeness, ErrorCode, MddError, MddResult, content_id};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnnotationRef {
    pub snapshot_id: String,
    pub dex_occurrence_id: String,
    pub annotation_byte_offset: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationOwnerRef {
    pub kind: AnnotationOwnerKind,
    pub reference: EntityRef,
    pub definition: Option<EntityRef>,
    pub parameter_ordinal: Option<u32>,
}
#[derive(Clone, Debug, Serialize)]
pub struct SignatureFact {
    pub annotation: AnnotationRef,
    pub owner: AnnotationOwnerRef,
    pub string_pool_id: String,
    pub parts: Vec<EntityRef>,
    pub utf16_units: Vec<u16>,
}
impl SignatureFact {
    pub fn strict_utf8(&self) -> Result<String, std::string::FromUtf16Error> {
        String::from_utf16(&self.utf16_units)
    }
}

#[derive(Clone, Serialize)]
/// Validated annotation facts expose only read-only getters.
/// ```compile_fail
/// fn alter(mut facts: mdd_facts::annotations::AnnotationFacts) { facts.data.values.clear(); }
/// ```
pub struct AnnotationFacts {
    definitions: DefinitionFacts,
    data: DexAnnotations,
    signatures: Vec<SignatureFact>,
    completed_layers: Vec<String>,
    unbuilt_layers: Vec<String>,
    annotation_coverage: Completeness,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnotationRelation {
    Directories,
    DirectoryEntries,
    SetEntries,
    SetRefs,
    Annotations,
    Elements,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationDirectoryRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub annotations_off: u32,
    pub class_annotations_off: Option<u32>,
    pub fields_size: u32,
    pub methods_size: u32,
    pub parameters_size: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationDirectoryEntryRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub annotations_off: u32,
    pub entry_kind: String,
    pub entry_idx: u32,
    pub annotation_set_off: Option<u32>,
    pub annotation_set_ref_list_off: Option<u32>,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationSetEntryRow {
    pub file_id: u32,
    pub annotation_set_off: u32,
    pub ordinal: u32,
    pub annotation_off: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationSetRefRow {
    pub file_id: u32,
    pub annotation_set_ref_list_off: u32,
    pub ordinal: u32,
    pub annotation_set_off: Option<u32>,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationRow {
    pub file_id: u32,
    pub annotation_off: u32,
    pub visibility: u32,
    pub type_idx: u32,
    pub element_count: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationElementRow {
    pub file_id: u32,
    pub annotation_off: u32,
    pub depth: u32,
    pub ordinal: u32,
    pub name_idx: Option<u32>,
    pub value_off: u32,
    pub value_end_off: u32,
    pub value_kind: String,
    pub value_index: Option<u32>,
    pub value_i64: Option<String>,
    pub value_f64: Option<ExactFloat>,
}

fn owner_ref(
    definitions: &DefinitionFacts,
    owner: &AnnotationOwnerBinding,
) -> MddResult<AnnotationOwnerRef> {
    let kind = match owner.kind {
        AnnotationOwnerKind::Class => EntityKind::ClassDefinition,
        AnnotationOwnerKind::Field => EntityKind::FieldReference,
        _ => EntityKind::MethodReference,
    };
    let reference = definitions.entity(kind, owner.local_index)?;
    let definition = match owner.kind {
        AnnotationOwnerKind::Class => Some(reference.clone()),
        AnnotationOwnerKind::Field => definitions
            .definitions
            .field_definitions
            .iter()
            .any(|field| field.field_idx == owner.local_index)
            .then(|| definitions.entity(EntityKind::FieldDefinition, owner.local_index))
            .transpose()?,
        _ => definitions
            .definitions
            .method_definitions
            .iter()
            .any(|method| method.method_idx == owner.local_index)
            .then(|| definitions.entity(EntityKind::MethodDefinition, owner.local_index))
            .transpose()?,
    };
    Ok(AnnotationOwnerRef {
        kind: owner.kind,
        reference,
        definition,
        parameter_ordinal: owner.parameter_ordinal,
    })
}

impl AnnotationFacts {
    pub fn build(definitions: DefinitionFacts, limits: AnnotationLimits) -> MddResult<Self> {
        let source = &definitions.metadata.source;
        let bind = |error: MddError| {
            error
                .detail("snapshot_id", source.snapshot_id.clone())
                .detail("dex_occurrence_id", source.dex_occurrence_id.clone())
                .detail("member_id", source.member_id.clone())
                .detail("content_id", source.content_id.clone())
        };
        if definitions.definition_coverage != Completeness::Complete {
            return Err(bind(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.annotations",
                "complete validated definitions required",
            )));
        }
        if content_id(definitions.bytes()) != source.content_id {
            return Err(bind(MddError::new(
                ErrorCode::InternalFault,
                "facts.annotations",
                "held bytes differ from captured source",
            )));
        }
        let data = read_annotations(
            definitions.bytes(),
            &definitions.metadata.header,
            &definitions.metadata,
            &definitions.definitions,
            limits,
        )
        .map_err(bind)?;
        let sets: BTreeMap<_, _> = data
            .sets
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        let items: BTreeMap<_, _> = data
            .annotation_items
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        let mut signatures = Vec::new();
        let mut remaining = limits
            .max_decoded_bytes
            .saturating_sub(data.usage.decoded_bytes);
        for owner in &data.owner_bindings {
            let Some(set) = owner.annotation_set_offset else {
                continue;
            };
            for offset in &sets[&set].annotation_offsets {
                let item = items[offset];
                if definitions.metadata.types[item.type_idx as usize]
                    .data
                    .descriptor
                    != "Ldalvik/annotation/Signature;"
                {
                    continue;
                }
                let invalid = || {
                    bind(MddError::new(ErrorCode::InvalidInput,"facts.annotations","Signature requires one named value containing an array of string references").detail("reason","SIGNATURE_SHAPE").detail("byte_offset",offset.to_string()))
                };
                if item.elements.len() != 1 {
                    return Err(invalid());
                }
                let value = &data.values[item.elements[0] as usize];
                let name = value
                    .name_idx
                    .and_then(|index| definitions.metadata.strings.get(index as usize))
                    .and_then(|item| item.data.text.strict_utf8().ok());
                if name.as_deref() != Some("value") || value.kind != EncodedKind::Array {
                    return Err(invalid());
                }
                let mut total_units = 0u64;
                for node_id in &value.children {
                    let part = &data.values[*node_id as usize];
                    if part.kind != EncodedKind::String {
                        return Err(invalid());
                    }
                    let index = part.value_index.ok_or_else(invalid)?;
                    total_units = total_units
                        .checked_add(
                            definitions.metadata.strings[index as usize]
                                .data
                                .text
                                .utf16_units
                                .len() as u64,
                        )
                        .ok_or_else(|| {
                            bind(MddError::new(
                                ErrorCode::QuotaExceeded,
                                "facts.annotations",
                                "Signature size overflow",
                            ))
                        })?;
                }
                let identity_bytes =
                    (source.snapshot_id.len() + source.dex_occurrence_id.len() + 32) as u64;
                let cost = total_units
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(value.children.len() as u64 * identity_bytes))
                    .and_then(|n| {
                        n.checked_add(
                            2 * identity_bytes
                                + definitions.metadata.string_pool.string_pool_id.len() as u64,
                        )
                    })
                    .ok_or_else(|| {
                        bind(MddError::new(
                            ErrorCode::QuotaExceeded,
                            "facts.annotations",
                            "Signature allocation size overflow",
                        ))
                    })?;
                remaining = remaining.checked_sub(cost).ok_or_else(|| {
                    bind(
                        MddError::new(
                            ErrorCode::QuotaExceeded,
                            "facts.annotations",
                            "Signature expansion exceeds annotation byte budget",
                        )
                        .detail("reason", "SIGNATURE_BYTE_BUDGET"),
                    )
                })?;
                let mut units = Vec::new();
                units.try_reserve_exact(total_units as usize).map_err(|_| {
                    bind(MddError::new(
                        ErrorCode::QuotaExceeded,
                        "facts.annotations",
                        "Signature allocation failed",
                    ))
                })?;
                let mut parts = Vec::new();
                parts.try_reserve_exact(value.children.len()).map_err(|_| {
                    bind(MddError::new(
                        ErrorCode::QuotaExceeded,
                        "facts.annotations",
                        "Signature reference allocation failed",
                    ))
                })?;
                for node_id in &value.children {
                    let index = data.values[*node_id as usize]
                        .value_index
                        .ok_or_else(invalid)?;
                    units.extend_from_slice(
                        &definitions.metadata.strings[index as usize]
                            .data
                            .text
                            .utf16_units,
                    );
                    parts.push(
                        definitions
                            .metadata
                            .entity(EntityKind::String, index)
                            .map_err(bind)?,
                    );
                }
                signatures.push(SignatureFact {
                    annotation: AnnotationRef {
                        snapshot_id: source.snapshot_id.clone(),
                        dex_occurrence_id: source.dex_occurrence_id.clone(),
                        annotation_byte_offset: *offset,
                    },
                    owner: owner_ref(&definitions, owner).map_err(bind)?,
                    string_pool_id: definitions.metadata.string_pool.string_pool_id.clone(),
                    parts,
                    utf16_units: units,
                });
            }
        }
        let mut completed_layers = definitions.completed_layers.clone();
        completed_layers.extend([
            "annotations".into(),
            "encoded_values".into(),
            "signature_fragments".into(),
        ]);
        let mut unbuilt_layers: Vec<_> = definitions
            .unbuilt_layers
            .iter()
            .filter(|layer| layer.as_str() != "annotations")
            .cloned()
            .collect();
        if data
            .parameter_lists
            .iter()
            .any(|binding| binding.prototype_position_coverage != Completeness::Complete)
        {
            unbuilt_layers.push("prototype_parameter_annotation_positions".into());
        }
        Ok(Self {
            definitions,
            data,
            signatures,
            completed_layers,
            unbuilt_layers,
            annotation_coverage: Completeness::Complete,
        })
    }
    pub fn definitions(&self) -> &DefinitionFacts {
        &self.definitions
    }
    pub fn source(&self) -> &MetadataSource {
        self.definitions.metadata.source()
    }
    pub fn data(&self) -> &DexAnnotations {
        &self.data
    }
    pub fn signatures(&self) -> &[SignatureFact] {
        &self.signatures
    }
    pub fn completed_layers(&self) -> &[String] {
        &self.completed_layers
    }
    pub fn unbuilt_layers(&self) -> &[String] {
        &self.unbuilt_layers
    }
    pub fn annotation_coverage(&self) -> Completeness {
        self.annotation_coverage
    }
    pub fn require_complete_parameter_positions(&self) -> MddResult<()> {
        if self
            .data
            .parameter_lists
            .iter()
            .any(|binding| binding.prototype_position_coverage != Completeness::Complete)
        {
            return Err(MddError::new(ErrorCode::IncompleteFacts,"facts.annotations","encoded parameter slots are complete, but complete prototype-position coverage is not established")
                .detail("required_layer","prototype_parameter_annotation_positions").detail("snapshot_id",self.source().snapshot_id.clone()).detail("dex_occurrence_id",self.source().dex_occurrence_id.clone()));
        }
        Ok(())
    }
    pub fn bytes(&self) -> &[u8] {
        self.definitions.bytes()
    }
    pub fn require_relation_columns(
        &self,
        relation: AnnotationRelation,
        columns: &[&str],
    ) -> MddResult<()> {
        let available: &[&str] = match relation {
            AnnotationRelation::Directories => &[
                "file_id",
                "class_idx",
                "annotations_off",
                "class_annotations_off",
                "fields_size",
                "methods_size",
                "parameters_size",
            ],
            AnnotationRelation::DirectoryEntries => &[
                "file_id",
                "class_idx",
                "annotations_off",
                "entry_kind",
                "entry_idx",
                "annotation_set_off",
                "annotation_set_ref_list_off",
            ],
            AnnotationRelation::SetEntries => {
                &["file_id", "annotation_set_off", "ordinal", "annotation_off"]
            }
            AnnotationRelation::SetRefs => &[
                "file_id",
                "annotation_set_ref_list_off",
                "ordinal",
                "annotation_set_off",
            ],
            AnnotationRelation::Annotations => &[
                "file_id",
                "annotation_off",
                "visibility",
                "type_idx",
                "element_count",
            ],
            AnnotationRelation::Elements => &[
                "file_id",
                "annotation_off",
                "depth",
                "ordinal",
                "name_idx",
                "value_off",
                "value_end_off",
                "value_kind",
                "value_index",
                "value_i64",
                "value_f64",
            ],
        };
        for column in columns {
            if *column != "*" && !available.contains(column) {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.annotations",
                    "unknown annotation relation column",
                )
                .detail("column", (*column).to_owned()));
            }
        }
        Ok(())
    }
    pub fn directory_rows(&self, file_id: u32) -> Vec<AnnotationDirectoryRow> {
        let items: BTreeMap<_, _> = self
            .data
            .directories
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        self.data
            .directory_bindings
            .iter()
            .map(|binding| {
                let item = items[&binding.directory_byte_offset];
                AnnotationDirectoryRow {
                    file_id,
                    class_idx: binding.class_idx,
                    annotations_off: item.byte_offset,
                    class_annotations_off: item.class_annotation_set_offset,
                    fields_size: item.fields_size,
                    methods_size: item.methods_size,
                    parameters_size: item.parameters_size,
                }
            })
            .collect()
    }
    pub fn directory_entry_rows(&self, file_id: u32) -> Vec<AnnotationDirectoryEntryRow> {
        let items: BTreeMap<_, _> = self
            .data
            .directories
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        self.data
            .directory_bindings
            .iter()
            .flat_map(|binding| {
                items[&binding.directory_byte_offset]
                    .entries
                    .iter()
                    .map(move |entry| AnnotationDirectoryEntryRow {
                        file_id,
                        class_idx: binding.class_idx,
                        annotations_off: binding.directory_byte_offset,
                        entry_kind: match entry.kind {
                            AnnotationOwnerKind::Field => "field",
                            AnnotationOwnerKind::Method => "method",
                            AnnotationOwnerKind::Parameter => "parameter",
                            AnnotationOwnerKind::Class => "class",
                        }
                        .into(),
                        entry_idx: entry.local_index,
                        annotation_set_off: (entry.kind != AnnotationOwnerKind::Parameter)
                            .then_some(entry.target_byte_offset),
                        annotation_set_ref_list_off: (entry.kind == AnnotationOwnerKind::Parameter)
                            .then_some(entry.target_byte_offset),
                    })
            })
            .collect()
    }
    pub fn set_entry_rows(&self, file_id: u32) -> Vec<AnnotationSetEntryRow> {
        self.data
            .sets
            .iter()
            .flat_map(|set| {
                set.annotation_offsets
                    .iter()
                    .enumerate()
                    .map(move |(ordinal, offset)| AnnotationSetEntryRow {
                        file_id,
                        annotation_set_off: set.byte_offset,
                        ordinal: ordinal as u32,
                        annotation_off: *offset,
                    })
            })
            .collect()
    }
    pub fn set_ref_rows(&self, file_id: u32) -> Vec<AnnotationSetRefRow> {
        self.data
            .ref_lists
            .iter()
            .flat_map(|list| {
                list.annotation_set_offsets
                    .iter()
                    .enumerate()
                    .map(move |(ordinal, offset)| AnnotationSetRefRow {
                        file_id,
                        annotation_set_ref_list_off: list.byte_offset,
                        ordinal: ordinal as u32,
                        annotation_set_off: *offset,
                    })
            })
            .collect()
    }
    pub fn annotation_rows(&self, file_id: u32) -> Vec<AnnotationRow> {
        self.data
            .annotation_items
            .iter()
            .map(|item| AnnotationRow {
                file_id,
                annotation_off: item.byte_offset,
                visibility: u32::from(item.visibility),
                type_idx: item.type_idx,
                element_count: item.elements.len() as u32,
            })
            .collect()
    }
    pub fn element_rows(&self, file_id: u32) -> Vec<AnnotationElementRow> {
        self.data
            .values
            .iter()
            .filter_map(|item| {
                item.annotation_byte_offset
                    .map(|root| AnnotationElementRow {
                        file_id,
                        annotation_off: root,
                        depth: item.depth,
                        ordinal: item.ordinal,
                        name_idx: item.name_idx,
                        value_off: item.encoded_range.byte_offset.0 as u32,
                        value_end_off: (item.encoded_range.byte_offset.0
                            + item.encoded_range.byte_length.0)
                            as u32,
                        value_kind: item.kind.as_str().into(),
                        value_index: item.value_index,
                        value_i64: item.value_i64.clone(),
                        value_f64: item.value_f64,
                    })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetadataFacts;
    use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
    use mdd_input::{
        archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
    };
    use std::path::PathBuf;
    fn build(path: &str) -> AnnotationFacts {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path,
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap();
        let inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap()
    }
    fn canonical(rows: &serde_json::Value) -> Vec<String> {
        let mut values = rows
            .as_array()
            .unwrap()
            .iter()
            .map(|row| serde_json::to_string(row).unwrap())
            .collect::<Vec<_>>();
        values.sort();
        values
    }
    #[test]
    fn six_full_relations_equal_independent_oracle_and_reference() {
        let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
        let reference: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/annotations/oracle-results.json"
        ))
        .unwrap();
        let data = &reference["positive"];
        for (name, native) in [
            (
                "annotation_directories",
                serde_json::to_value(facts.directory_rows(0)).unwrap(),
            ),
            (
                "annotation_directory_entries",
                serde_json::to_value(facts.directory_entry_rows(0)).unwrap(),
            ),
            (
                "annotation_set_entries",
                serde_json::to_value(facts.set_entry_rows(0)).unwrap(),
            ),
            (
                "annotation_set_refs",
                serde_json::to_value(facts.set_ref_rows(0)).unwrap(),
            ),
            (
                "annotations",
                serde_json::to_value(facts.annotation_rows(0)).unwrap(),
            ),
            (
                "annotation_elements",
                serde_json::to_value(facts.element_rows(0)).unwrap(),
            ),
        ] {
            assert_eq!(canonical(&native), canonical(&data[name]), "{name}");
        }
        assert!(
            facts
                .require_relation_columns(AnnotationRelation::Elements, &["*"])
                .is_ok()
        );
        assert_eq!(
            facts
                .require_relation_columns(AnnotationRelation::Elements, &["value_i65"])
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    #[test]
    fn signature_parts_keep_array_order_pool_and_owner_source() {
        let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/annotations/expected.json"
        ))
        .unwrap();
        assert_eq!(facts.signatures.len(), 4);
        for signature in &facts.signatures {
            let key = match signature.owner.kind {
                AnnotationOwnerKind::Class => "class".to_owned(),
                AnnotationOwnerKind::Field => {
                    format!("field:{}", signature.owner.reference.local_index)
                }
                AnnotationOwnerKind::Method => {
                    format!("method:{}", signature.owner.reference.local_index)
                }
                AnnotationOwnerKind::Parameter => {
                    panic!("fixture parameter has Values, not Signature")
                }
            };
            assert_eq!(
                signature.strict_utf8().unwrap(),
                expected["signatures"][key].as_str().unwrap()
            );
            assert_eq!(
                signature.string_pool_id,
                facts.definitions.metadata.string_pool.string_pool_id
            );
            assert!(
                signature
                    .parts
                    .iter()
                    .all(|part| part.snapshot_id == facts.source().snapshot_id
                        && part.dex_occurrence_id == facts.source().dex_occurrence_id
                        && part.kind == EntityKind::String)
            );
        }
        let other = build("tests/fixtures/annotations/generated/annotations-038.dex");
        assert_ne!(facts.signatures[0].parts[0], other.signatures[0].parts[0]);
        assert_eq!(
            facts.signatures[0].string_pool_id,
            other.signatures[0].string_pool_id
        );
        assert_eq!(facts.annotation_coverage, Completeness::Complete);
        assert!(
            facts
                .unbuilt_layers
                .iter()
                .any(|layer| layer == "code_layout")
        );
    }

    #[test]
    fn same_snapshot_duplicate_occurrences_keep_distinct_annotation_refs() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let mut facts = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            let definitions =
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
            facts.push(AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap());
        }
        assert_eq!(facts[0].source().snapshot_id, facts[1].source().snapshot_id);
        assert_ne!(
            facts[0].signatures()[0].annotation,
            facts[1].signatures()[0].annotation
        );
        assert_ne!(
            facts[0].signatures()[0].parts[0],
            facts[1].signatures()[0].parts[0]
        );
        assert_eq!(
            facts[0].signatures()[0].string_pool_id,
            facts[1].signatures()[0].string_pool_id
        );
        drop(snapshot);
        assert_eq!(facts[0].bytes(), facts[1].bytes());
    }

    #[test]
    fn short_parameter_lists_have_explicit_unknown_prototype_coverage() {
        let facts = build("tests/fixtures/annotations/generated/bad-parameter-arity.dex");
        assert_eq!(facts.annotation_coverage(), Completeness::Complete);
        assert_eq!(facts.set_ref_rows(0).len(), 1);
        let error = facts.require_complete_parameter_positions().unwrap_err();
        assert_eq!(error.code, ErrorCode::IncompleteFacts);
        assert_eq!(
            error.details["required_layer"],
            "prototype_parameter_annotation_positions"
        );
        assert!(
            facts
                .unbuilt_layers()
                .iter()
                .any(|layer| layer == "prototype_parameter_annotation_positions")
        );
    }
}
