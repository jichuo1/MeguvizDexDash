use super::*;
use serde_json::Value;

fn counts() -> Counts {
    Counts {
        strings: 16,
        types: 16,
        fields: 16,
        methods: 16,
        prototypes: 16,
        call_sites: 16,
        handles: 16,
    }
}

fn fragment(
    words: &[u16],
    registers: u16,
    outs: u16,
    version: u16,
) -> MddResult<(Vec<Instruction>, Vec<Payload>, Vec<SwitchTargets>)> {
    decode::decode(
        words,
        DecodeContext {
            base: 128,
            registers,
            outs,
            counts: counts(),
            version,
            limits: CodeLimits::default(),
        },
        &mut Used::default(),
    )
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/instructions/generated")
            .join(name),
    )
    .unwrap()
}

fn parse_file(bytes: &[u8]) -> MddResult<CodeSection> {
    parse_file_policy(bytes, DebugPolicy::EncodedFactsV1)
}

fn parse_file_policy(bytes: &[u8], policy: DebugPolicy) -> MddResult<CodeSection> {
    let header = crate::validate_header(bytes)?;
    read_code_section(
        bytes,
        &header,
        CodeLimits {
            debug_policy: policy,
            ..CodeLimits::default()
        },
    )
}

fn resign(bytes: &mut [u8]) {
    use sha1::{Digest, Sha1};
    let hash = Sha1::digest(&bytes[32..]);
    bytes[12..32].copy_from_slice(&hash);
    let (mut a, mut b) = (1u32, 0u32);
    for value in &bytes[12..] {
        a = (a + u32::from(*value)) % 65521;
        b = (b + a) % 65521;
    }
    bytes[8..12].copy_from_slice(&((b << 16) | a).to_le_bytes());
}

#[test]
fn every_active_opcode_and_format_is_actually_decoded_and_reserved_items_fail() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/instructions/generated/all-opcodes.json"
    ))
    .unwrap();
    let vectors = data["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 224);
    let mut formats = BTreeSet::new();
    for vector in vectors {
        let words: Vec<_> = vector["words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as u16)
            .collect();
        let (instructions, _, _) = fragment(&words, 512, 255, 40)
            .unwrap_or_else(|error| panic!("opcode {}: {error}", vector["opcode"]));
        let first = &instructions[0];
        assert_eq!(u64::from(first.opcode), vector["opcode"].as_u64().unwrap());
        assert_eq!(first.mnemonic, vector["mnemonic"].as_str().unwrap());
        assert_eq!(first.format, vector["format"].as_str().unwrap());
        assert_eq!(
            u64::from(first.width_code_units),
            vector["expected_first_width"].as_u64().unwrap()
        );
        assert_eq!(first.instruction_ordinal, 0);
        assert_eq!(first.byte_offset, DecimalU64(128));
        formats.insert(first.format.clone());
    }
    assert_eq!(formats.len(), 26);
    let reserved: Vec<_> = opcodes::OPCODES
        .iter()
        .enumerate()
        .filter(|(_, i)| i.reserved)
        .collect();
    assert_eq!(reserved.len(), 32);
    for (opcode, _) in reserved {
        let error = fragment(&[opcode as u16, 0x000e], 16, 16, 40).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert_eq!(error.details["reason"], "RESERVED_OPCODE");
    }
}

#[test]
fn hand_expected_operands_literals_ranges_and_dynamic_invokes_remain_distinct() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/instructions/generated/manual-expectations.json"
    ))
    .unwrap();
    for vector in data["vectors"].as_array().unwrap() {
        let words: Vec<_> = vector["words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as u16)
            .collect();
        let (instructions, _, _) = fragment(&words, 512, 255, 40).unwrap();
        let item = &instructions[0];
        let expected: Vec<_> = vector["registers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as u16)
            .collect();
        assert_eq!(item.registers, expected, "{}", vector["id"]);
        if let Some(literal) = vector.get("literal") {
            assert_eq!(
                item.literal.as_ref().unwrap().signed_decimal,
                literal.as_str().unwrap()
            );
        }
        for (field, kind) in [
            ("method_idx", ReferenceKind::Method),
            ("prototype_idx", ReferenceKind::Prototype),
            ("call_site_idx", ReferenceKind::CallSite),
        ] {
            if let Some(index) = vector.get(field) {
                assert!(
                    item.references
                        .iter()
                        .any(|r| r.kind == kind
                            && u64::from(r.local_index) == index.as_u64().unwrap())
                );
            }
        }
        if vector["id"] == "custom-not-ordinary" {
            assert_eq!(item.invoke_kind, Some(InvokeKind::Custom));
            assert!(
                !item
                    .references
                    .iter()
                    .any(|r| r.kind == ReferenceKind::Method)
            );
        }
    }
    let (ordinary, _, _) = fragment(&[0x106e, 3, 0, 0x000e], 16, 8, 40).unwrap();
    let (range, _, _) = fragment(&[0x0174, 3, 0, 0x000e], 16, 8, 40).unwrap();
    let (poly, _, _) = fragment(&[0x10fa, 3, 0, 4, 0x000e], 16, 8, 40).unwrap();
    let (custom, _, _) = fragment(&[0x01fd, 3, 0, 0x000e], 16, 8, 40).unwrap();
    assert_eq!(ordinary[0].invoke_kind, Some(InvokeKind::Ordinary));
    assert_eq!(range[0].invoke_kind, Some(InvokeKind::OrdinaryRange));
    assert_eq!(poly[0].references.len(), 2);
    assert_eq!(custom[0].invoke_kind, Some(InvokeKind::CustomRange));
    assert_eq!(custom[0].references[0].kind, ReferenceKind::CallSite);
    assert_eq!(
        ordinary[0].references[0].raw_range.byte_offset.0,
        ordinary[0].byte_offset.0 + 2
    );
    assert_eq!(ordinary[0].references[0].raw_range.byte_length.0, 2);
    assert_eq!(
        poly[0].references[1].raw_range.byte_offset.0,
        poly[0].byte_offset.0 + 6
    );
    assert_eq!(poly[0].references[1].raw_range.byte_length.0, 2);
    let (jumbo, _, _) = fragment(&[0x001b, 7, 0, 0x000e], 16, 8, 40).unwrap();
    assert_eq!(
        jumbo[0].references[0].raw_range.byte_offset.0,
        jumbo[0].byte_offset.0 + 2
    );
    assert_eq!(jumbo[0].references[0].raw_range.byte_length.0, 4);
    let (poly_range, _, _) = fragment(&[0x01fb, 3, 0, 4, 0x000e], 16, 8, 40).unwrap();
    assert_eq!(
        poly_range[0].references[1].raw_range.byte_offset.0,
        poly_range[0].byte_offset.0 + 6
    );
}

#[test]
fn malformed_width_register_wide_range_branch_payload_and_index_cases_fail() {
    let cases: Vec<(&[u16], u16, u16)> = vec![
        (&[0x0090], 16, 16),
        (&[0x010e], 16, 16),
        (&[0x1001, 0x000e], 1, 16),
        (&[0x0116, 0, 0x000e], 2, 16),
        (&[0x0274, 0, 0xffff, 0x000e], u16::MAX, 16),
        (&[0x606e, 0, 0, 0x000e], 16, 16),
        (&[0x006e, 0, 0, 0x000e], 16, 16),
        (&[0x106e, 0, 0, 0x000e], 16, 0),
        (&[0x0228, 0x0014, 0, 0, 0x000e], 16, 16),
        (&[0x7f28], 16, 16),
        (&[0x000e, 0x0300, 1, 1, 0, 0], 16, 16),
        (&[0x0026, 3, 0, 0x000e], 16, 16),
        (&[0x002b, 4, 0, 0x000e, 0x0300, 1, 1, 0, 0], 16, 16),
        (
            &[0x002c, 4, 0, 0x000e, 0x0200, 2, 3, 0, 1, 0, 3, 0, 3, 0],
            16,
            16,
        ),
        (&[0x000e, 0, 0x0300, 3, 1, 0, 0], 16, 16),
        (&[0x0428, 0x000e, 0, 0, 0x0300, 1, 1, 0, 0], 16, 16),
        (&[0x0400], 16, 16),
    ];
    for (words, registers, outs) in cases {
        let error = fragment(words, registers, outs, 40).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidInput, "{words:?}: {error}");
        assert_eq!(error.details["facts_layer"], "code_layout");
    }
    for words in [
        &[0x001a, 16, 0x000e][..],
        &[0x001c, 16, 0x000e],
        &[0x0052, 16, 0x000e],
        &[0x106e, 16, 0, 0x000e],
        &[0x00ff, 16, 0x000e],
        &[0x10fc, 16, 0, 0x000e],
        &[0x00fe, 16, 0x000e],
    ] {
        assert_eq!(
            fragment(words, 16, 16, 40).unwrap_err().details["reason"],
            "INSTRUCTION_REFERENCE_OUT_OF_RANGE"
        );
    }
    assert!(fragment(&[0x10fa, 0, 0, 0, 0x000e], 16, 16, 37).is_err());
    assert!(fragment(&[0x00fe, 0, 0x000e], 16, 16, 38).is_err());
    for version in [35, 37, 38, 39, 40] {
        assert!(fragment(&[0x000e], 0, 0, version).is_ok());
    }
}

#[test]
fn full_map_includes_unreferenced_code_and_offsets_have_explicit_narrow_scope() {
    let bytes = fixture("unreferenced-two-code.dex");
    let header = crate::validate_header(&bytes).unwrap();
    let all = read_code_section(&bytes, &header, CodeLimits::default()).unwrap();
    assert_eq!(all.declared_code_item_count, 2);
    assert_eq!(all.items.len(), 2);
    assert_eq!(all.items[0].raw_range.byte_offset, DecimalU64(112));
    assert_eq!(all.items[1].raw_range.byte_offset, DecimalU64(132));
    assert!(all.items[1].debug_info.is_some());
    let selected =
        read_code_offsets(&bytes, &header, &[132, 112, 132], CodeLimits::default()).unwrap();
    assert!(selected.scope.starts_with("explicit-code-offsets"));
    assert_eq!(
        selected
            .items
            .iter()
            .map(|i| i.raw_range.byte_offset.0)
            .collect::<Vec<_>>(),
        [132, 112, 132]
    );
    assert!(read_code_offsets(&bytes, &header, &[114], CodeLimits::default()).is_err());
    assert!(!all.full_dex_validation_complete);
    for version in [b"035", b"037", b"038", b"039", b"040"] {
        let mut variant = bytes.clone();
        variant[4..7].copy_from_slice(version);
        resign(&mut variant);
        let parsed = parse_file(&variant).unwrap();
        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].insns_range.byte_length, DecimalU64(2));
    }
    for version in [b"036", b"041"] {
        let mut variant = bytes.clone();
        variant[4..7].copy_from_slice(version);
        resign(&mut variant);
        assert_eq!(
            parse_file(&variant).unwrap_err().code,
            ErrorCode::UnsupportedCapability
        );
    }
    for name in ["bad-reserved-opcode.dex", "bad-truncated-wide.dex"] {
        assert_eq!(
            parse_file(&fixture(name)).unwrap_err().code,
            ErrorCode::InvalidInput
        );
    }
}

#[test]
fn payload_units_raw_ranges_targets_and_repetition_are_exact() {
    let packed = parse_file(&fixture("packed-switch.dex")).unwrap();
    let item = &packed.items[0];
    assert_eq!(item.insns_size_code_units, 10);
    assert_eq!(item.instructions.len(), 2);
    assert_eq!(item.payloads[0].code_unit_offset, 4);
    assert_eq!(item.payloads[0].width_code_units, 6);
    assert_eq!(item.switch_targets[0].target_code_units, [3]);
    assert_eq!(item.instructions[1].instruction_ordinal, 1);
    assert_eq!(item.instructions[1].code_unit_offset, 3);
    assert_eq!(item.instructions[1].byte_offset, DecimalU64(134));
    let sparse = parse_file(&fixture("sparse-switch.dex")).unwrap();
    assert_eq!(sparse.items[0].switch_targets[0].target_code_units, [3, 3]);
    let array = parse_file(&fixture("fill-array.dex")).unwrap();
    if let PayloadData::FillArray {
        element_count,
        data_range,
        ..
    } = &array.items[0].payloads[0].data
    {
        assert_eq!(*element_count, 3);
        assert_eq!(data_range.byte_length, DecimalU64(3));
        assert_eq!(
            &fixture("fill-array.dex")
                [data_range.byte_offset.0 as usize..(data_range.byte_offset.0 + 3) as usize],
            &[1, 2, 3]
        );
    } else {
        panic!("wrong payload type");
    }
    let (_, _, switches) = fragment(
        &[0, 0, 0x002b, 4, 0, 0x000e, 0x0100, 1, 0, 0, 3, 0],
        16,
        16,
        40,
    )
    .unwrap();
    assert_eq!(switches[0].target_code_units, [5]);
    let (backward, _, _) = fragment(&[0, 0, 0xfe28], 16, 16, 40).unwrap();
    assert_eq!(backward[2].branch_target_code_units, Some(0));
}

#[test]
fn tries_padding_handler_origin_and_catch_all_targets_are_bounded() {
    let original = fixture("try-catch-all.dex");
    let section = parse_file(&original).unwrap();
    let item = &section.items[0];
    assert_eq!(item.tries[0].start_code_unit, 0);
    assert_eq!(item.handlers[0].relative_byte_offset, 1);
    assert_eq!(item.handlers[0].catch_all_address_code_units, Some(1));
    assert_eq!(item.insns_range.byte_length, DecimalU64(6));
    assert_eq!(item.raw_range.byte_length, DecimalU64(35));
    for (offset, value) in [(134, 1u8), (142, 0), (140, 4), (146, 3)] {
        let mut bytes = original.clone();
        bytes[offset] = value;
        resign(&mut bytes);
        assert!(crate::validate_header(&bytes).is_ok());
        assert!(parse_file(&bytes).is_err(), "mutant at {offset}");
    }
}

#[test]
fn debug_all_opcodes_no_index_and_pc_line_register_failures_are_visible() {
    let original = fixture("all-debug-opcodes.dex");
    let section = parse_file(&original).unwrap();
    let debug = section.items[0].debug_info.as_ref().unwrap();
    assert_eq!(debug.initial_line, 2);
    assert!(debug.parameter_name_indices.is_empty());
    let ops: BTreeSet<_> = debug.events.iter().map(|e| e.opcode).collect();
    for op in 0..=9 {
        assert!(ops.contains(&op));
    }
    assert!(
        debug.events.iter().any(|e| e.emits_position
            && e.address_code_units == 0
            && e.encoded_line_decimal == "1")
    );
    assert!(
        debug
            .events
            .iter()
            .filter(|e| matches!(e.opcode, 3 | 4))
            .all(|e| e.name_idx.is_none() && e.type_idx.is_none())
    );
    let at = debug.raw_range.byte_offset.0 as usize;
    for (relative, value) in [(7usize, 1u8), (3, 2), (8, 1)] {
        let mut bytes = original.clone();
        bytes[at + relative] = value;
        resign(&mut bytes);
        assert!(crate::validate_header(&bytes).is_ok());
        if relative == 3 {
            assert!(parse_file(&bytes).is_ok());
            assert_eq!(
                parse_file_policy(&bytes, DebugPolicy::StrictSourceLinesV1)
                    .unwrap_err()
                    .code,
                ErrorCode::IncompleteFacts
            );
        } else {
            assert!(parse_file(&bytes).is_err(), "debug mutant {relative}");
        }
    }
    let header = crate::validate_header(&original).unwrap();
    let limits = CodeLimits {
        max_debug_operations: 0,
        ..CodeLimits::default()
    };
    assert_eq!(
        read_code_section(&original, &header, limits)
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
}

#[test]
fn limits_are_cumulative_and_zero_never_means_unlimited() {
    let bytes = fixture("unreferenced-two-code.dex");
    let header = crate::validate_header(&bytes).unwrap();
    for limits in [
        CodeLimits {
            max_code_items: 1,
            ..CodeLimits::default()
        },
        CodeLimits {
            max_total_code_units: 1,
            ..CodeLimits::default()
        },
        CodeLimits {
            max_instructions: 1,
            ..CodeLimits::default()
        },
    ] {
        assert_eq!(
            read_code_section(&bytes, &header, limits).unwrap_err().code,
            ErrorCode::QuotaExceeded
        );
    }
    let bytes = fixture("try-catch-all.dex");
    let header = crate::validate_header(&bytes).unwrap();
    assert_eq!(
        read_code_section(
            &bytes,
            &header,
            CodeLimits {
                max_catch_pairs: 0,
                ..CodeLimits::default()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::QuotaExceeded
    );
    let bytes = fixture("packed-switch.dex");
    let header = crate::validate_header(&bytes).unwrap();
    assert_eq!(
        read_code_section(
            &bytes,
            &header,
            CodeLimits {
                max_payload_elements: 0,
                ..CodeLimits::default()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::QuotaExceeded
    );
}

#[test]
fn shared_payload_expansion_and_duplicate_offset_projection_each_consume_budget() {
    let words = [
        0x002b, 8, 0, 0x002b, 5, 0, 0x000e, 0x000e, 0x0100, 1, 0, 0, 3, 0,
    ];
    let limits = CodeLimits {
        max_payload_elements: 1,
        max_switch_targets: 1,
        ..CodeLimits::default()
    };
    let error = decode::decode(
        &words,
        DecodeContext {
            base: 128,
            registers: 1,
            outs: 0,
            counts: counts(),
            version: 40,
            limits,
        },
        &mut Used::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.details["budget"], "max_switch_targets");
    assert_eq!(error.details["observed"], "2");
    let bytes = fixture("unreferenced-two-code.dex");
    let header = crate::validate_header(&bytes).unwrap();
    for limits in [
        CodeLimits {
            max_code_items: 3,
            max_total_code_units: 2,
            ..CodeLimits::default()
        },
        CodeLimits {
            max_code_items: 3,
            max_instructions: 2,
            ..CodeLimits::default()
        },
    ] {
        let error = read_code_offsets(&bytes, &header, &[112, 112, 112], limits).unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.details["observed"], "3");
    }
}

#[test]
fn debug_references_must_name_physical_item_starts_and_outs_layout_is_checked() {
    let mut bytes = fixture("unreferenced-two-code.dex");
    bytes[140..144].copy_from_slice(&151u32.to_le_bytes());
    resign(&mut bytes);
    let header = crate::validate_header(&bytes).unwrap();
    let error = read_code_section(&bytes, &header, CodeLimits::default()).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(error.details["reason"], "DEBUG_OFFSET_NOT_ITEM_START");
    assert_eq!(error.details["code_item_byte_offset"], "132");
    assert_eq!(error.details["debug_info_byte_offset"], "151");
    let mut bytes = fixture("unreferenced-two-code.dex");
    bytes[116..118].copy_from_slice(&6u16.to_le_bytes());
    resign(&mut bytes);
    assert_eq!(
        parse_file(&bytes).unwrap_err().details["reason"],
        "OUTS_EXCEEDS_REGISTER_LAYOUT"
    );
    bytes[116..118].copy_from_slice(&5u16.to_le_bytes());
    resign(&mut bytes);
    assert!(parse_file(&bytes).is_ok());
    for opcode in [0x0025, 0x0077, 0x00fd] {
        assert_eq!(
            fragment(&[opcode, 0, 0xffff, 0x000e], 0, 0, 40)
                .unwrap_err()
                .details["reason"],
            "REGISTER_RANGE_OUT_OF_BOUNDS"
        );
        assert!(fragment(&[opcode, 0, 0, 0x000e], 0, 0, 40).is_ok());
    }
}

#[test]
fn debug_state_only_operations_and_try_ends_preserve_format_permitted_positions() {
    for opcode in [7, 8, 9] {
        let section =
            parse_file(&fixture(&format!("debug-intermediate-state-{opcode}.dex"))).unwrap();
        let events = &section.items[0].debug_info.as_ref().unwrap().events;
        assert!(
            events
                .iter()
                .any(|e| e.opcode == opcode && e.address_code_units == 1 && !e.emits_position)
        );
        assert!(events.iter().any(|e| e.emits_position
            && e.address_code_units == 3
            && e.encoded_line_decimal == "1"));
    }
    let section = parse_file(&fixture("try-end-inside-instruction.dex")).unwrap();
    assert_eq!(section.items[0].instructions[0].width_code_units, 3);
    assert_eq!(section.items[0].tries[0].code_unit_count, 1);
    for name in [
        "bad-debug-initial-zero.dex",
        "bad-debug-advance-zero.dex",
        "bad-debug-special-negative.dex",
    ] {
        let bytes = fixture(name);
        assert!(parse_file(&bytes).is_ok());
        let error = parse_file_policy(&bytes, DebugPolicy::StrictSourceLinesV1).unwrap_err();
        assert_eq!(error.code, ErrorCode::IncompleteFacts);
        assert_eq!(
            error.details["reason"], "DEBUG_LINE_LESS_THAN_ONE",
            "{name}"
        );
    }
    assert!(parse_file(&fixture("bad-debug-missing-end.dex")).is_err());
}

#[test]
fn shared_pc_to_pc_pattern_keeps_complete_raw_events_and_explicit_method_projection() {
    for base in [0, 1] {
        let bytes = fixture(&format!("pc-to-pc-shared-base-{base}.dex"));
        let section = parse_file(&bytes).unwrap();
        assert_eq!(section.items.len(), 2);
        let short = section.items[0].debug_info.as_ref().unwrap();
        let longer = section.items[1].debug_info.as_ref().unwrap();
        assert!(matches!(
            short.representation,
            DebugRepresentation::PcToPcPattern
        ));
        assert_eq!(short.raw_range.byte_offset, longer.raw_range.byte_offset);
        assert_eq!(short.raw_range.byte_length, longer.raw_range.byte_length);
        assert_eq!(short.events.len(), 7);
        assert_eq!(longer.events.len(), 7);
        assert_eq!(short.raw_position_count, DecimalU64(6));
        assert_eq!(short.applicable_method_position_count, DecimalU64(1));
        assert_eq!(longer.applicable_method_position_count, DecimalU64(4));
        assert_eq!(
            short
                .method_positions()
                .map(|e| e.address_code_units)
                .collect::<Vec<_>>(),
            [0]
        );
        assert_eq!(
            longer
                .method_positions()
                .map(|e| e.address_code_units)
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert_eq!(
            short.events[0].code_item_address_scope,
            DebugAddressScope::InsideCodeUnits
        );
        assert_eq!(
            short.events[1].code_item_address_scope,
            DebugAddressScope::AtCodeEnd
        );
        assert_eq!(
            short.events[2].code_item_address_scope,
            DebugAddressScope::BeyondCodeEnd
        );
        assert_eq!(short.events[5].address_code_units, 5);
        assert_eq!(short.events[5].encoded_line_decimal, (5 + base).to_string());
        let header = crate::validate_header(&bytes).unwrap();
        let error = read_code_section(
            &bytes,
            &header,
            CodeLimits {
                max_debug_operations: 10,
                ..CodeLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
    }
    let wide = parse_file(&fixture("debug-line-u32max.dex")).unwrap();
    assert_eq!(
        wide.items[0].debug_info.as_ref().unwrap().events[0].encoded_line_decimal,
        "4294967295"
    );
    for (name, reason) in [
        ("bad-debug-line-overflow.dex", "DEBUG_LINE_OVERFLOW"),
        (
            "bad-debug-parameter-count.dex",
            "DEBUG_PARAMETER_COUNT_EXCEEDS_FORMAT",
        ),
    ] {
        assert_eq!(
            parse_file(&fixture(name)).unwrap_err().details["reason"],
            reason
        );
    }
    let bytes = fixture("bad-debug-nonpattern-shared-suffix.dex");
    assert!(parse_file(&bytes).is_ok());
    assert_eq!(
        parse_file_policy(&bytes, DebugPolicy::StrictSourceLinesV1)
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn encoded_unknown_source_lines_are_retained_and_strict_source_policy_still_fails() {
    let bytes = fixture("debug-observed-zero-source-line.dex");
    let section = parse_file(&bytes).unwrap();
    let debug = section.items[0].debug_info.as_ref().unwrap();
    assert_eq!(debug.debug_policy, DebugPolicy::EncodedFactsV1);
    assert!(!debug.strict_positive_line_policy_satisfied);
    let zero = debug
        .events
        .iter()
        .find(|event| event.emits_position && event.address_code_units == 18)
        .unwrap();
    assert_eq!(zero.encoded_line_decimal, "0");
    assert_eq!(zero.source_line, None);
    assert!(!zero.source_line_usable);
    assert_eq!(zero.source_line_kind, SourceLineKind::UnknownNonPositive);
    let restored = debug
        .events
        .iter()
        .find(|event| event.emits_position && event.address_code_units == 34)
        .unwrap();
    assert_eq!(restored.encoded_line_decimal, "32");
    assert_eq!(restored.source_line, Some(DecimalU64(32)));
    assert!(restored.source_line_usable);
    assert_eq!(debug.unusable_method_source_position_count, DecimalU64(1));
    assert_eq!(debug.method_positions().count(), 12);
    assert_eq!(debug.usable_source_positions().count(), 11);
    let error = parse_file_policy(&bytes, DebugPolicy::StrictSourceLinesV1).unwrap_err();
    assert_eq!(error.code, ErrorCode::IncompleteFacts);
    assert_eq!(error.stage, "debug.source_line_policy");
    assert_eq!(error.details["encoded_debug_complete"], true);
    assert_eq!(error.details["facts_layer"], "source_positions");
    for base in [0, 1] {
        let bytes = fixture(&format!("pc-to-pc-shared-base-{base}.dex"));
        let parsed = parse_file(&bytes).unwrap();
        let debug = parsed.items[0].debug_info.as_ref().unwrap();
        assert!(
            debug
                .events
                .iter()
                .filter(|event| event.emits_position)
                .all(|event| !event.source_line_usable
                    && event.source_line.is_none()
                    && event.source_line_kind == SourceLineKind::PcSurrogate)
        );
        assert_eq!(
            parse_file_policy(&bytes, DebugPolicy::StrictSourceLinesV1)
                .unwrap_err()
                .code,
            ErrorCode::IncompleteFacts
        );
    }
    let positive = fixture("all-debug-opcodes.dex");
    let strict = parse_file_policy(&positive, DebugPolicy::StrictSourceLinesV1).unwrap();
    assert!(
        strict.items[0]
            .debug_info
            .as_ref()
            .unwrap()
            .strict_positive_line_policy_satisfied
    );
}
