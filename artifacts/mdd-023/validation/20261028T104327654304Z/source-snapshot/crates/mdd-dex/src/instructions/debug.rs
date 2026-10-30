use super::*;

pub(super) struct DebugContext {
    pub registers: u16,
    pub size: u32,
    pub counts: Counts,
    pub limits: CodeLimits,
}

/// Walk each declared variable-length debug item once. Mere containment in the
/// debug section does not prove that a reference names an actual item start.
pub(super) fn item_starts(
    bytes: &[u8],
    header: &DexHeader,
    limits: CodeLimits,
    used: &mut Used,
) -> MddResult<BTreeSet<u64>> {
    let Some((start, end, count)) = section(header, 0x2003) else {
        return Ok(BTreeSet::new());
    };
    let reader = CheckedReader::new(bytes);
    let counts = Counts::from_header(header);
    let mut at = start;
    let mut starts = BTreeSet::new();
    for _ in 0..count {
        bounded_range(reader, at, 1, start, end)?;
        starts.insert(at);
        leb_u(bytes, &mut at, end)?;
        let parameters = leb_u(bytes, &mut at, end)?;
        if parameters > 65536 {
            return Err(fail("DEBUG_PARAMETER_COUNT_EXCEEDS_FORMAT", at, 0));
        }
        charge(
            &mut used.debug_operations,
            u64::from(parameters),
            limits.max_debug_operations,
            "max_debug_operations",
            at,
        )?;
        for _ in 0..parameters {
            optional_index(bytes, &mut at, end, counts.strings, "parameter_name")?;
        }
        loop {
            charge(
                &mut used.debug_operations,
                1,
                limits.max_debug_operations,
                "max_debug_operations",
                at,
            )?;
            bounded_range(reader, at, 1, start, end)?;
            let opcode = reader.range(at, 1)?[0];
            at += 1;
            match opcode {
                0 => break,
                1 | 5 | 6 => {
                    leb_u(bytes, &mut at, end)?;
                }
                2 => {
                    leb_s(bytes, &mut at, end)?;
                }
                3 | 4 => {
                    leb_u(bytes, &mut at, end)?;
                    optional_index(bytes, &mut at, end, counts.strings, "local_name")?;
                    optional_index(bytes, &mut at, end, counts.types, "local_type")?;
                    if opcode == 4 {
                        optional_index(bytes, &mut at, end, counts.strings, "local_signature")?;
                    }
                }
                9 => {
                    optional_index(bytes, &mut at, end, counts.strings, "source_file")?;
                }
                _ => (),
            }
        }
    }
    Ok(starts)
}

fn optional_index(
    bytes: &[u8],
    at: &mut u64,
    end: u64,
    count: u32,
    kind: &str,
) -> MddResult<Option<u32>> {
    let value = leb_u(bytes, at, end)?;
    if value == 0 {
        return Ok(None);
    }
    let index = value - 1;
    if index >= count {
        return Err(fail("DEBUG_INDEX_OUT_OF_RANGE", *at, 0)
            .detail("kind", kind)
            .detail("index", u64::from(index)));
    }
    Ok(Some(index))
}

pub(super) fn parse(
    bytes: &[u8],
    header: &DexHeader,
    offset: u64,
    context: DebugContext,
    used: &mut Used,
) -> MddResult<DebugInfo> {
    let DebugContext {
        registers,
        size,
        counts,
        limits,
    } = context;
    let (start, end, _) =
        section(header, 0x2003).ok_or_else(|| fail("MISSING_DEBUG_INFO_SECTION", offset, 0))?;
    let reader = CheckedReader::new(bytes);
    bounded_range(reader, offset, 1, start, end)?;
    let mut at = offset;
    let initial_line = leb_u(bytes, &mut at, end)?;
    let mut line = i64::from(initial_line);
    let mut invalid_source_line = if line < 1 { Some(offset) } else { None };
    let mut outside_code = None;
    let parameters = leb_u(bytes, &mut at, end)?;
    if parameters > 65536 {
        return Err(fail("DEBUG_PARAMETER_COUNT_EXCEEDS_FORMAT", at, 0));
    }
    charge(
        &mut used.debug_operations,
        u64::from(parameters),
        limits.max_debug_operations,
        "max_debug_operations",
        at,
    )?;
    let mut names = Vec::new();
    for _ in 0..parameters {
        names.push(optional_index(
            bytes,
            &mut at,
            end,
            counts.strings,
            "parameter_name",
        )?);
    }
    let mut events = Vec::new();
    let mut pc = 0u32;
    loop {
        charge(
            &mut used.debug_operations,
            1,
            limits.max_debug_operations,
            "max_debug_operations",
            at,
        )?;
        bounded_range(reader, at, 1, start, end)?;
        let event_at = at;
        let opcode = reader.range(at, 1)?[0];
        at += 1;
        let mut register = None;
        let mut name = None;
        let mut type_idx = None;
        let mut signature = None;
        let mut file = None;
        let mut position = false;
        match opcode {
            0 => (),
            1 => {
                let amount = leb_u(bytes, &mut at, end)?;
                pc = pc
                    .checked_add(amount)
                    .ok_or_else(|| fail("DEBUG_PC_OVERFLOW", event_at, at - event_at))?;
                if pc > size {
                    outside_code.get_or_insert(event_at);
                }
            }
            2 => {
                let delta = leb_s(bytes, &mut at, end)?;
                line = line
                    .checked_add(i64::from(delta))
                    .ok_or_else(|| fail("DEBUG_LINE_OVERFLOW", event_at, at - event_at))?;
            }
            3 | 4 => {
                let reg = leb_u(bytes, &mut at, end)?;
                if reg >= u32::from(registers) {
                    return Err(fail("DEBUG_REGISTER_OUT_OF_RANGE", event_at, at - event_at));
                }
                register = Some(reg as u16);
                name = optional_index(bytes, &mut at, end, counts.strings, "local_name")?;
                type_idx = optional_index(bytes, &mut at, end, counts.types, "local_type")?;
                if opcode == 4 {
                    signature =
                        optional_index(bytes, &mut at, end, counts.strings, "local_signature")?;
                }
            }
            5 | 6 => {
                let reg = leb_u(bytes, &mut at, end)?;
                if reg >= u32::from(registers) {
                    return Err(fail("DEBUG_REGISTER_OUT_OF_RANGE", event_at, at - event_at));
                }
                register = Some(reg as u16);
            }
            7 | 8 => (),
            9 => {
                file = optional_index(bytes, &mut at, end, counts.strings, "source_file")?;
            }
            _ => {
                let adjusted = u32::from(opcode) - 10;
                pc = pc
                    .checked_add(adjusted / 15)
                    .ok_or_else(|| fail("DEBUG_PC_OVERFLOW", event_at, 1))?;
                line = line
                    .checked_add(-4 + i64::from(adjusted % 15))
                    .ok_or_else(|| fail("DEBUG_LINE_OVERFLOW", event_at, 1))?;
                if pc > size {
                    outside_code.get_or_insert(event_at);
                }
                position = true;
            }
        }
        if line < 1 {
            invalid_source_line.get_or_insert(event_at);
        }
        if line > i64::from(u32::MAX) || line < i64::from(i32::MIN) {
            return Err(fail("DEBUG_LINE_OVERFLOW", event_at, at - event_at));
        }
        events.push(DebugEvent {
            byte_offset: DecimalU64(event_at),
            opcode,
            address_code_units: pc,
            encoded_line_decimal: line.to_string(),
            source_line: None,
            source_line_usable: false,
            source_line_kind: SourceLineKind::NotAPosition,
            register,
            name_idx: name,
            type_idx,
            signature_idx: signature,
            file_idx: file,
            emits_position: position,
            code_item_address_scope: if pc < size {
                DebugAddressScope::InsideCodeUnits
            } else if pc == size {
                DebugAddressScope::AtCodeEnd
            } else {
                DebugAddressScope::BeyondCodeEnd
            },
        });
        if opcode == 0 {
            break;
        }
    }
    // R8 writes one zero-change position followed by (PC+1,line+1) positions,
    // with unnamed parameters. The whole physical item can be shared by shorter
    // methods. Recognition describes this encoding, not the APK's producer.
    let pc_to_pc = initial_line <= 1
        && names.iter().all(Option::is_none)
        && events.len() >= 2
        && events[0].opcode == 0x0e
        && events.last().is_some_and(|event| event.opcode == 0)
        && events[1..events.len() - 1]
            .iter()
            .all(|event| event.opcode == 0x1e);
    if limits.debug_policy == DebugPolicy::StrictSourceLinesV1 {
        let semantic_error = |reason: &str, at: u64| {
            let mut error = fail(reason, at, 0);
            error.code = ErrorCode::IncompleteFacts;
            error.stage = "debug.source_line_policy".to_owned();
            error
                .detail("required_layer", "source_positions")
                .detail("facts_layer", "source_positions")
                .detail("input_coverage", "unknown")
                .detail("debug_policy", "mdd-debug-source-lines-strict-v1")
                .detail("encoded_debug_complete", true)
                .detail("current_code_item_layout_complete", true)
        };
        if pc_to_pc {
            return Err(semantic_error(
                "DEBUG_PC_SURROGATE_REQUIRES_SOURCE_MAPPING",
                offset,
            ));
        }
        if let Some(at) = invalid_source_line {
            return Err(semantic_error("DEBUG_LINE_LESS_THAN_ONE", at));
        }
        if let Some(at) = outside_code {
            return Err(semantic_error("DEBUG_PC_OUTSIDE_CODE", at));
        }
    }
    for event in &mut events {
        event.source_line_kind = if !event.emits_position {
            SourceLineKind::NotAPosition
        } else if pc_to_pc {
            SourceLineKind::PcSurrogate
        } else if event.encoded_line_decimal.starts_with('-') || event.encoded_line_decimal == "0" {
            SourceLineKind::UnknownNonPositive
        } else if event.code_item_address_scope != DebugAddressScope::InsideCodeUnits {
            SourceLineKind::OutsideCodeContext
        } else {
            SourceLineKind::PositiveEncodedLine
        };
        if event.source_line_kind == SourceLineKind::PositiveEncodedLine {
            event.source_line = Some(DecimalU64(
                event.encoded_line_decimal.parse::<u64>().map_err(|_| {
                    fail("DEBUG_LINE_INTERNAL_REPRESENTATION", event.byte_offset.0, 0)
                })?,
            ));
            event.source_line_usable = true;
        }
    }
    let raw_positions = events.iter().filter(|event| event.emits_position).count() as u64;
    let applicable = events
        .iter()
        .filter(|event| {
            event.emits_position
                && event.code_item_address_scope == DebugAddressScope::InsideCodeUnits
        })
        .count() as u64;
    let usable = events
        .iter()
        .filter(|event| event.source_line_usable)
        .count() as u64;
    Ok(DebugInfo {raw_range:range(offset,at-offset),initial_line,parameter_name_indices:names,events,
        representation:if pc_to_pc {DebugRepresentation::PcToPcPattern} else {DebugRepresentation::EventProgram},
        referring_code_unit_length:size,raw_position_count:DecimalU64(raw_positions),applicable_method_position_count:DecimalU64(applicable),
        usable_method_source_position_count:DecimalU64(usable),unusable_method_source_position_count:DecimalU64(applicable-usable),
        debug_policy:limits.debug_policy,strict_positive_line_policy_satisfied:limits.debug_policy==DebugPolicy::StrictSourceLinesV1,
        validation_scope:"complete bounded physical debug program; pc-to-pc encoding retains shared suffix with explicit code-range tags; borrowed method view is address < code size; parameter/prototype and local lifetimes require method binding".to_owned()})
}
