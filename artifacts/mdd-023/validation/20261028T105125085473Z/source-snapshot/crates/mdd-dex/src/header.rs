use crate::checked_reader::{CheckedReader, invalid};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, BTreeSet};

const HEADER_SIZE: u64 = 112;
const SCOPE: &str = "standard-le-header-map-fixed-references-v2";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DexRange {
    pub byte_offset: DecimalU64,
    pub byte_length: DecimalU64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TableInfo {
    pub name: String,
    pub count: u32,
    pub range: DexRange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MapItem {
    pub type_code: u16,
    pub name: String,
    pub count: u32,
    pub byte_offset: DecimalU64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DexHeader {
    pub version: String,
    pub file_size: DecimalU64,
    pub header_range: DexRange,
    pub data_range: DexRange,
    pub link_range: Option<DexRange>,
    pub endian: String,
    pub declared_checksum: u32,
    pub checksum_verified: bool,
    pub declared_signature_sha1: String,
    pub signature_verified: bool,
    pub tables: Vec<TableInfo>,
    pub map: Vec<MapItem>,
    pub validated_scope: String,
    pub full_dex_validation_complete: bool,
}

fn failure(reason: &str, stage: &str, offset: u64, length: u64) -> MddError {
    invalid(reason, stage, offset, length).detail("validated_scope", SCOPE)
}

fn unsupported(reason: &str, offset: u64, length: u64) -> MddError {
    let mut error = failure(reason, "dex.header", offset, length);
    error.code = ErrorCode::UnsupportedCapability;
    error
}

fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in bytes.chunks(5552) {
        for value in chunk {
            a += u32::from(*value);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

fn item_shape(kind: u16) -> Option<(&'static str, u64, u64)> {
    Some(match kind {
        0x0000 => ("header", 112, 4),
        0x0001 => ("string_ids", 4, 4),
        0x0002 => ("type_ids", 4, 4),
        0x0003 => ("proto_ids", 12, 4),
        0x0004 => ("field_ids", 8, 4),
        0x0005 => ("method_ids", 8, 4),
        0x0006 => ("class_defs", 32, 4),
        0x0007 => ("call_site_ids", 4, 4),
        0x0008 => ("method_handles", 8, 4),
        0x1000 => ("map_list", 4, 4),
        0x1001 => ("type_list", 4, 4),
        0x1002 => ("annotation_set_ref_list", 4, 4),
        0x1003 => ("annotation_set", 4, 4),
        0x2000 => ("class_data", 4, 1),
        0x2001 => ("code", 16, 4),
        0x2002 => ("string_data", 2, 1),
        0x2003 => ("debug_info", 3, 1),
        0x2004 => ("annotation", 3, 1),
        0x2005 => ("encoded_array", 1, 1),
        0x2006 => ("annotations_directory", 16, 4),
        0xf000 => ("hiddenapi_class_data", 4, 4),
        _ => return None,
    })
}

struct MapSection {
    count: u32,
    start: u64,
    end: u64,
}

fn in_section(
    sections: &BTreeMap<u16, MapSection>,
    kind: u16,
    offset: u32,
    length: u64,
) -> MddResult<()> {
    let offset = u64::from(offset);
    let section = sections.get(&kind).ok_or_else(|| {
        failure(
            "MISSING_REFERENCED_MAP_SECTION",
            "dex.references",
            offset,
            length,
        )
        .detail("map_type", u64::from(kind))
    })?;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| failure("REFERENCE_RANGE_OVERFLOW", "dex.references", offset, length))?;
    if offset < section.start || end > section.end {
        return Err(failure(
            "REFERENCE_OUTSIDE_SECTION",
            "dex.references",
            offset,
            length,
        )
        .detail("map_type", u64::from(kind))
        .detail("section_start", section.start.to_string())
        .detail("section_end", section.end.to_string()));
    }
    Ok(())
}

fn index(value: u32, count: u32, offset: u64, table: &str) -> MddResult<()> {
    if value >= count {
        return Err(failure("INDEX_OUT_OF_RANGE", "dex.references", offset, 4)
            .detail("referenced_table", table)
            .detail("index", u64::from(value))
            .detail("table_count", u64::from(count)));
    }
    Ok(())
}

fn type_list(
    reader: CheckedReader<'_>,
    sections: &BTreeMap<u16, MapSection>,
    offset: u32,
    type_count: u32,
    seen: &mut BTreeSet<u32>,
) -> MddResult<()> {
    if offset == 0 || seen.contains(&offset) {
        return Ok(());
    }
    if !offset.is_multiple_of(4) {
        return Err(failure(
            "UNALIGNED_TYPE_LIST",
            "dex.references",
            u64::from(offset),
            4,
        ));
    }
    in_section(sections, 0x1001, offset, 4)?;
    let count = reader.u32(u64::from(offset))?;
    let length = 4 + u64::from(count) * 2;
    in_section(sections, 0x1001, offset, length)?;
    reader.range(u64::from(offset), length)?;
    for ordinal in 0..count {
        let at = u64::from(offset) + 4 + u64::from(ordinal) * 2;
        index(u32::from(reader.u16(at)?), type_count, at, "type_ids")?;
    }
    seen.insert(offset);
    Ok(())
}

/// Validate a caller-held standard little-endian DEX slice without reopening a path.
/// Success covers the explicit M1 scope, not strings, code, annotations or ART semantics.
pub fn validate_header(bytes: &[u8]) -> MddResult<DexHeader> {
    let reader = CheckedReader::new(bytes);
    let magic = reader.range(0, 8)?;
    if magic.starts_with(b"cdex") || magic.starts_with(b"vdex") || magic.starts_with(b"oat\n") {
        return Err(unsupported("SPECIAL_CONTAINER_UNSUPPORTED", 0, 8));
    }
    if &magic[..4] != b"dex\n" || magic[7] != 0 || !magic[4..7].iter().all(u8::is_ascii_digit) {
        return Err(failure("INVALID_MAGIC", "dex.header", 0, 8));
    }
    let version = match &magic[4..7] {
        b"035" => "035",
        b"037" => "037",
        b"038" => "038",
        b"039" => "039",
        b"040" => "040",
        _ => {
            return Err(unsupported("DEX_VERSION_UNSUPPORTED", 4, 3).detail(
                "version",
                String::from_utf8_lossy(&magic[4..7]).into_owned(),
            ));
        }
    };
    reader.range(0, HEADER_SIZE)?;
    let endian = reader.u32(40)?;
    if endian == 0x78563412 {
        return Err(unsupported("REVERSE_ENDIAN_UNSUPPORTED", 40, 4));
    }
    if endian != 0x12345678 {
        return Err(failure("INVALID_ENDIAN_TAG", "dex.header", 40, 4));
    }
    let file_size = reader.u32(32)?;
    if u64::from(file_size) != reader.len() {
        return Err(failure("FILE_SIZE_MISMATCH", "dex.header", 32, 4)
            .detail("declared_file_bytes", file_size.to_string())
            .detail("captured_file_bytes", reader.len().to_string()));
    }
    if reader.u32(36)? != HEADER_SIZE as u32 {
        return Err(failure("INVALID_HEADER_SIZE", "dex.header", 36, 4));
    }
    let checksum = reader.u32(8)?;
    if adler32(reader.range(12, reader.len() - 12)?) != checksum {
        return Err(failure("CHECKSUM_MISMATCH", "dex.header", 8, 4));
    }
    if Sha1::digest(reader.range(32, reader.len() - 32)?).as_slice() != reader.range(12, 20)? {
        return Err(failure("SIGNATURE_SHA1_MISMATCH", "dex.header", 12, 20));
    }
    let signature = reader
        .range(12, 20)?
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect();
    let data_size = reader.u32(104)?;
    let data_off = reader.u32(108)?;
    if data_size == 0
        || u64::from(data_off) < HEADER_SIZE
        || data_off % 4 != 0
        || data_size % 4 != 0
    {
        return Err(failure("INVALID_DATA_RANGE", "dex.header", 104, 8));
    }
    reader.range(u64::from(data_off), u64::from(data_size))?;
    let data_end = u64::from(data_off) + u64::from(data_size);
    let mut tables = Vec::new();
    let mut previous_end = HEADER_SIZE;
    for (kind, header_offset) in [(1, 56u64), (2, 64), (3, 72), (4, 80), (5, 88), (6, 96)] {
        let count = reader.u32(header_offset)?;
        let offset = reader.u32(header_offset + 4)?;
        let (name, stride, _) = item_shape(kind)
            .ok_or_else(|| failure("UNKNOWN_FIXED_TABLE", "dex.header", header_offset, 8))?;
        let length = u64::from(count) * stride;
        if (count == 0 && offset != 0)
            || (count > 0 && (u64::from(offset) < previous_end || offset % 4 != 0))
        {
            return Err(
                failure("INVALID_TABLE_OFFSET", "dex.tables", header_offset, 8)
                    .detail("table", name),
            );
        }
        if count > 0 {
            reader.array(u64::from(offset), u64::from(count), stride)?;
            previous_end = u64::from(offset) + length;
            if previous_end > u64::from(data_off) {
                return Err(failure(
                    "TABLE_OVERLAPS_DATA",
                    "dex.tables",
                    u64::from(offset),
                    length,
                )
                .detail("table", name));
            }
        }
        tables.push(TableInfo {
            name: name.to_owned(),
            count,
            range: DexRange {
                byte_offset: DecimalU64(u64::from(offset)),
                byte_length: DecimalU64(length),
            },
        });
    }
    if tables[1].count > 65535 || tables[2].count > 65535 {
        return Err(failure(
            "TYPE_OR_PROTO_COUNT_EXCEEDS_FORMAT",
            "dex.tables",
            64,
            16,
        ));
    }
    let link_size = reader.u32(44)?;
    let link_off = reader.u32(48)?;
    let link_range = if link_size == 0 {
        if link_off != 0 {
            return Err(failure("EMPTY_LINK_HAS_OFFSET", "dex.header", 44, 8));
        }
        None
    } else {
        reader.range(u64::from(link_off), u64::from(link_size))?;
        if u64::from(link_off) < data_end {
            return Err(failure(
                "LINK_OVERLAPS_VALIDATED_SECTIONS",
                "dex.header",
                u64::from(link_off),
                u64::from(link_size),
            ));
        }
        Some(DexRange {
            byte_offset: DecimalU64(u64::from(link_off)),
            byte_length: DecimalU64(u64::from(link_size)),
        })
    };
    let map_off = reader.u32(52)?;
    if map_off % 4 != 0 || map_off < data_off || u64::from(map_off) + 4 > data_end {
        return Err(failure("INVALID_MAP_OFFSET", "dex.map", 52, 4));
    }
    let map_count = reader.u32(u64::from(map_off))?;
    if map_count == 0 || map_count > 21 {
        return Err(failure(
            "INVALID_MAP_COUNT",
            "dex.map",
            u64::from(map_off),
            4,
        ));
    }
    let map_length = 4 + u64::from(map_count) * 12;
    if u64::from(map_off) + map_length > data_end {
        return Err(failure(
            "TRUNCATED_MAP",
            "dex.map",
            u64::from(map_off),
            map_length,
        ));
    }
    reader.range(u64::from(map_off), map_length)?;
    let mut map = Vec::new();
    let mut unique = BTreeSet::new();
    let mut previous_minimum_end = 0;
    for ordinal in 0..map_count {
        let at = u64::from(map_off) + 4 + u64::from(ordinal) * 12;
        let kind = reader.u16(at)?;
        let count = reader.u32(at + 4)?;
        let offset = reader.u32(at + 8)?;
        let Some((name, stride, alignment)) = item_shape(kind) else {
            return Err(
                failure("UNKNOWN_MAP_TYPE", "dex.map", at, 2).detail("map_type", u64::from(kind))
            );
        };
        if reader.u16(at + 2)? != 0 || count == 0 || !unique.insert(kind) {
            return Err(failure("INVALID_OR_DUPLICATE_MAP_ITEM", "dex.map", at, 12));
        }
        if ((kind == 7 || kind == 8) && version < "038") || (kind == 0xf000 && version < "039") {
            return Err(failure("MAP_TYPE_INVALID_FOR_VERSION", "dex.map", at, 12));
        }
        let minimum_length = if kind == 0x1000 {
            map_length
        } else {
            u64::from(count) * stride
        };
        if u64::from(offset) < previous_minimum_end || u64::from(offset) % alignment != 0 {
            return Err(failure(
                "OVERLAPPING_OR_UNALIGNED_MAP_ITEM",
                "dex.map",
                at,
                12,
            ));
        }
        reader.range(u64::from(offset), minimum_length)?;
        if kind >= 0x1000 && (offset < data_off || u64::from(offset) + minimum_length > data_end) {
            return Err(failure("MAP_ITEM_OUTSIDE_DATA", "dex.map", at, 12));
        }
        previous_minimum_end = u64::from(offset) + minimum_length;
        map.push(MapItem {
            type_code: kind,
            name: name.to_owned(),
            count,
            byte_offset: DecimalU64(u64::from(offset)),
        });
    }
    for (kind, count, offset) in
        [(0, 1, 0), (0x1000, 1, map_off)]
            .into_iter()
            .chain(tables.iter().enumerate().map(|(i, table)| {
                (
                    (i + 1) as u16,
                    table.count,
                    table.range.byte_offset.0 as u32,
                )
            }))
    {
        let item = map.iter().find(|entry| entry.type_code == kind);
        if (count == 0 && item.is_some())
            || (count > 0
                && !item.is_some_and(|entry| {
                    entry.count == count && entry.byte_offset.0 == u64::from(offset)
                }))
        {
            return Err(failure(
                "HEADER_MAP_DISAGREEMENT",
                "dex.map",
                u64::from(map_off),
                map_length,
            )
            .detail("map_type", u64::from(kind)));
        }
    }
    let mut sections = BTreeMap::new();
    for (ordinal, item) in map.iter().enumerate() {
        let end = map
            .get(ordinal + 1)
            .map_or(data_end, |next| next.byte_offset.0);
        sections.insert(
            item.type_code,
            MapSection {
                count: item.count,
                start: item.byte_offset.0,
                end,
            },
        );
    }
    let [strings, types, protos, fields, methods, classes] = tables.as_slice() else {
        return Err(failure("INTERNAL_TABLE_LAYOUT", "dex.tables", 0, 0));
    };
    if strings.count > 0 && !sections.contains_key(&0x2002) {
        return Err(failure(
            "MISSING_STRING_DATA_MAP_SECTION",
            "dex.references",
            56,
            8,
        ));
    }
    let mut seen_lists = BTreeSet::new();
    for ordinal in 0..strings.count {
        let at = strings.range.byte_offset.0 + u64::from(ordinal) * 4;
        in_section(&sections, 0x2002, reader.u32(at)?, 2)?;
    }
    for ordinal in 0..types.count {
        let at = types.range.byte_offset.0 + u64::from(ordinal) * 4;
        index(reader.u32(at)?, strings.count, at, "string_ids")?;
    }
    for ordinal in 0..protos.count {
        let at = protos.range.byte_offset.0 + u64::from(ordinal) * 12;
        index(reader.u32(at)?, strings.count, at, "string_ids")?;
        index(reader.u32(at + 4)?, types.count, at + 4, "type_ids")?;
        type_list(
            reader,
            &sections,
            reader.u32(at + 8)?,
            types.count,
            &mut seen_lists,
        )?;
    }
    for ordinal in 0..fields.count {
        let at = fields.range.byte_offset.0 + u64::from(ordinal) * 8;
        index(u32::from(reader.u16(at)?), types.count, at, "type_ids")?;
        index(
            u32::from(reader.u16(at + 2)?),
            types.count,
            at + 2,
            "type_ids",
        )?;
        index(reader.u32(at + 4)?, strings.count, at + 4, "string_ids")?;
    }
    for ordinal in 0..methods.count {
        let at = methods.range.byte_offset.0 + u64::from(ordinal) * 8;
        index(u32::from(reader.u16(at)?), types.count, at, "type_ids")?;
        index(
            u32::from(reader.u16(at + 2)?),
            protos.count,
            at + 2,
            "proto_ids",
        )?;
        index(reader.u32(at + 4)?, strings.count, at + 4, "string_ids")?;
    }
    let mut class_types = BTreeSet::new();
    for ordinal in 0..classes.count {
        let at = classes.range.byte_offset.0 + u64::from(ordinal) * 32;
        let class_type = reader.u32(at)?;
        index(class_type, types.count, at, "type_ids")?;
        if !class_types.insert(class_type) {
            return Err(failure(
                "DUPLICATE_CLASS_DEFINITION",
                "dex.references",
                at,
                4,
            ));
        }
        for (delta, count, target) in [
            (8, types.count, "type_ids"),
            (16, strings.count, "string_ids"),
        ] {
            let value = reader.u32(at + delta)?;
            if value != u32::MAX {
                index(value, count, at + delta, target)?;
            }
        }
        type_list(
            reader,
            &sections,
            reader.u32(at + 12)?,
            types.count,
            &mut seen_lists,
        )?;
        for (delta, kind, minimum, alignment) in
            [(20, 0x2006, 16, 4), (24, 0x2000, 4, 1), (28, 0x2005, 1, 1)]
        {
            let value = reader.u32(at + delta)?;
            if value != 0 {
                if value % alignment != 0 {
                    return Err(failure(
                        "UNALIGNED_REFERENCE",
                        "dex.references",
                        at + delta,
                        4,
                    ));
                }
                in_section(&sections, kind, value, minimum)?;
            }
        }
    }
    if let Some(section) = sections.get(&7) {
        for ordinal in 0..section.count {
            let at = section.start + u64::from(ordinal) * 4;
            in_section(&sections, 0x2005, reader.u32(at)?, 1)?;
        }
    }
    if let Some(section) = sections.get(&8) {
        for ordinal in 0..section.count {
            let at = section.start + u64::from(ordinal) * 8;
            let handle_type = reader.u16(at)?;
            if handle_type > 8 || reader.u16(at + 2)? != 0 || reader.u16(at + 6)? != 0 {
                return Err(failure("INVALID_METHOD_HANDLE", "dex.references", at, 8));
            }
            index(
                u32::from(reader.u16(at + 4)?),
                if handle_type <= 3 {
                    fields.count
                } else {
                    methods.count
                },
                at + 4,
                if handle_type <= 3 {
                    "field_ids"
                } else {
                    "method_ids"
                },
            )?;
        }
    }
    Ok(DexHeader {
        version: version.to_owned(),
        file_size: DecimalU64(u64::from(file_size)),
        header_range: DexRange {
            byte_offset: DecimalU64(0),
            byte_length: DecimalU64(HEADER_SIZE),
        },
        data_range: DexRange {
            byte_offset: DecimalU64(u64::from(data_off)),
            byte_length: DecimalU64(u64::from(data_size)),
        },
        link_range,
        endian: "little".to_owned(),
        declared_checksum: checksum,
        checksum_verified: true,
        declared_signature_sha1: signature,
        signature_verified: true,
        tables,
        map,
        validated_scope: SCOPE.to_owned(),
        full_dex_validation_complete: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &[u8] = include_bytes!("../../../tests/fixtures/generated/minimal-035.dex");
    const STRUCTURED: &[u8] =
        include_bytes!("../../../tests/fixtures/generated/structured-035.dex");

    fn mutate(data: &[u8], offset: usize, value: u32) -> Vec<u8> {
        let mut changed = data.to_vec();
        changed[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        let signature = Sha1::digest(&changed[32..]);
        changed[12..32].copy_from_slice(&signature);
        let checksum = adler32(&changed[12..]);
        changed[8..12].copy_from_slice(&checksum.to_le_bytes());
        changed
    }

    fn reason(error: &MddError) -> &str {
        error.details["reason"].as_str().unwrap()
    }

    #[test]
    fn each_standard_version_has_real_fixture() {
        for (version, bytes) in [
            ("035", MINIMAL),
            (
                "037",
                include_bytes!("../../../tests/fixtures/generated/minimal-037.dex").as_slice(),
            ),
            (
                "038",
                include_bytes!("../../../tests/fixtures/generated/minimal-038.dex").as_slice(),
            ),
            (
                "039",
                include_bytes!("../../../tests/fixtures/generated/minimal-039.dex").as_slice(),
            ),
            (
                "040",
                include_bytes!("../../../tests/fixtures/generated/minimal-040.dex").as_slice(),
            ),
        ] {
            let header = validate_header(bytes).unwrap();
            assert_eq!(header.version, version);
            assert!(header.checksum_verified);
            assert!(header.signature_verified && !header.full_dex_validation_complete);
            assert_eq!(header.map.len(), 2);
            let value = serde_json::to_value(&header).unwrap();
            assert_eq!(value["file_size"], "140");
        }
    }

    #[test]
    fn exact_unsupported_formats_do_not_admit_numeric_ranges() {
        for bytes in [
            include_bytes!("../../../tests/fixtures/generated/unsupported-036.dex").as_slice(),
            include_bytes!("../../../tests/fixtures/generated/unsupported-041.dex").as_slice(),
            b"cdex001\0",
            b"vdex019\0",
            b"oat\n170\0",
        ] {
            assert_eq!(
                validate_header(bytes).unwrap_err().code,
                ErrorCode::UnsupportedCapability
            );
        }
        assert_eq!(
            validate_header(&mutate(MINIMAL, 40, 0x78563412))
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedCapability
        );
        assert_eq!(
            reason(&validate_header(&mutate(MINIMAL, 40, 9)).unwrap_err()),
            "INVALID_ENDIAN_TAG"
        );
    }

    #[test]
    fn structured_sources_and_reordered_data_keep_valid_reference_ranges() {
        for bytes in [
            STRUCTURED,
            include_bytes!("../../../tests/fixtures/generated/strings-mutf8-035.dex").as_slice(),
            include_bytes!("../../../tests/fixtures/generated/class-reorder-before.dex").as_slice(),
            include_bytes!("../../../tests/fixtures/generated/class-reorder-after.dex").as_slice(),
        ] {
            validate_header(bytes).unwrap();
        }
        let header = validate_header(STRUCTURED).unwrap();
        assert_eq!(
            header
                .tables
                .iter()
                .map(|table| table.count)
                .collect::<Vec<_>>(),
            [7, 3, 1, 0, 4, 1]
        );
    }

    #[test]
    fn malformed_fixtures_have_distinct_errors_and_ranges() {
        for (bytes, expected) in [
            (
                include_bytes!("../../../tests/fixtures/generated/bad-magic.dex").as_slice(),
                "INVALID_MAGIC",
            ),
            (
                include_bytes!("../../../tests/fixtures/generated/truncated-header.dex").as_slice(),
                "TRUNCATED_RANGE",
            ),
            (
                include_bytes!("../../../tests/fixtures/generated/bad-checksum.dex").as_slice(),
                "CHECKSUM_MISMATCH",
            ),
            (
                include_bytes!("../../../tests/fixtures/generated/bad-map-offset.dex").as_slice(),
                "OVERLAPPING_OR_UNALIGNED_MAP_ITEM",
            ),
            (
                include_bytes!("../../../tests/fixtures/generated/table-count-overflow.dex")
                    .as_slice(),
                "TRUNCATED_RANGE",
            ),
        ] {
            let error = validate_header(bytes).unwrap_err();
            assert_eq!(reason(&error), expected);
            assert_eq!(error.code, ErrorCode::InvalidInput);
            assert!(error.stage.starts_with("dex."));
            assert_eq!(error.details["facts_coverage"], "unknown");
            assert!(
                error.details.contains_key("byte_offset")
                    && error.details.contains_key("byte_length")
            );
        }
    }

    #[test]
    fn map_overlap_duplicate_and_header_disagreement_are_errors() {
        for bytes in [
            mutate(MINIMAL, 128, 0),
            mutate(MINIMAL, 132, 2),
            mutate(MINIMAL, 136, 108),
            mutate(MINIMAL, 112, u32::MAX),
        ] {
            assert_eq!(
                validate_header(&bytes).unwrap_err().code,
                ErrorCode::InvalidInput
            );
        }
        assert_eq!(
            reason(&validate_header(&mutate(MINIMAL, 52, 0)).unwrap_err()),
            "INVALID_MAP_OFFSET"
        );
    }

    #[test]
    fn forward_backwards_and_out_of_range_references_are_rejected() {
        for (offset, value, expected) in [
            (112, 0, "REFERENCE_OUTSIDE_SECTION"),
            (112, u32::MAX, "REFERENCE_OUTSIDE_SECTION"),
            (140, 7, "INDEX_OUT_OF_RANGE"),
            (152, 7, "INDEX_OUT_OF_RANGE"),
            (156, 3, "INDEX_OUT_OF_RANGE"),
            (168, 7, "INDEX_OUT_OF_RANGE"),
            (196, 3, "INDEX_OUT_OF_RANGE"),
            (220, 112, "REFERENCE_OUTSIDE_SECTION"),
        ] {
            assert_eq!(
                reason(&validate_header(&mutate(STRUCTURED, offset, value)).unwrap_err()),
                expected,
                "offset={offset}"
            );
        }
    }

    #[test]
    fn all_prefix_truncations_fail_without_panic() {
        for length in 0..STRUCTURED.len() {
            assert!(
                validate_header(&STRUCTURED[..length]).is_err(),
                "prefix length {length}"
            );
        }
    }

    #[test]
    fn checksum_and_sha1_validation_scopes_remain_distinct() {
        let error = validate_header(include_bytes!(
            "../../../tests/fixtures/generated/bad-signature.dex"
        ))
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert_eq!(reason(&error), "SIGNATURE_SHA1_MISMATCH");
        assert_eq!(error.details["byte_offset"], "12");
    }

    #[test]
    fn header_empty_ranges_and_large_counts_fail_explicitly() {
        for (bytes, expected) in [
            (mutate(MINIMAL, 36, 108), "INVALID_HEADER_SIZE"),
            (mutate(MINIMAL, 32, 139), "FILE_SIZE_MISMATCH"),
            (mutate(MINIMAL, 60, 112), "INVALID_TABLE_OFFSET"),
            (mutate(MINIMAL, 48, 112), "EMPTY_LINK_HAS_OFFSET"),
            (mutate(MINIMAL, 104, u32::MAX), "INVALID_DATA_RANGE"),
            (mutate(MINIMAL, 104, u32::MAX - 3), "TRUNCATED_RANGE"),
            (mutate(MINIMAL, 108, 0), "INVALID_DATA_RANGE"),
            (mutate(MINIMAL, 116, 0x9999), "UNKNOWN_MAP_TYPE"),
        ] {
            let error = validate_header(&bytes).unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidInput);
            assert_eq!(reason(&error), expected);
        }
    }
}
