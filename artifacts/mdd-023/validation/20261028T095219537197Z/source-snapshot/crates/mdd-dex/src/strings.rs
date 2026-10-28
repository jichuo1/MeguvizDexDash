//! Lossless DEX string values and bounded 32-bit LEB decoding.
use crate::{
    DexHeader, DexRange,
    checked_reader::{CheckedReader, invalid},
};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::{Deserialize, Serialize};

pub const LEB_PROFILE: &str = "bounded-permissive-leb32-v1";

#[derive(Clone, Copy, Debug)]
pub struct StringLimits {
    pub max_strings: u32,
    pub max_string_bytes: u64,
    pub max_total_code_units: u64,
}

impl Default for StringLimits {
    fn default() -> Self {
        Self {
            max_strings: 4_000_000,
            max_string_bytes: 16 * 1024 * 1024,
            max_total_code_units: 128 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DexText {
    pub raw_mutf8: Vec<u8>,
    pub utf16_units: Vec<u16>,
    pub declared_utf16_length: u32,
    pub declared_length_verified: bool,
    pub raw_range: DexRange,
}

impl DexText {
    pub fn strict_utf8(&self) -> Result<String, std::string::FromUtf16Error> {
        String::from_utf16(&self.utf16_units)
    }

    pub fn display_lossy(&self) -> String {
        String::from_utf16_lossy(&self.utf16_units)
    }

    pub fn equals_raw(&self, other: &Self) -> bool {
        self.raw_mutf8 == other.raw_mutf8
    }

    pub fn equals_utf16(&self, other: &Self) -> bool {
        self.utf16_units == other.utf16_units
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DexString {
    pub string_idx: u32,
    pub data_range: DexRange,
    pub text: DexText,
}

fn failure(reason: &str, offset: u64, length: u64) -> MddError {
    invalid(reason, "dex.strings", offset, length)
}

fn quota(reason: &str, offset: u64, length: u64) -> MddError {
    let mut error = failure(reason, offset, length);
    error.code = ErrorCode::QuotaExceeded;
    error
}

fn leb(bytes: &[u8], offset: u64, end: u64, signed: bool) -> MddResult<(i64, u64)> {
    let reader = CheckedReader::new(bytes);
    if offset > end || end > reader.len() {
        return Err(failure("LEB_RANGE", offset, end.saturating_sub(offset)));
    }
    let mut value = 0i64;
    for ordinal in 0..5u64 {
        let at = offset
            .checked_add(ordinal)
            .ok_or_else(|| failure("LEB_RANGE_OVERFLOW", offset, ordinal))?;
        if at >= end {
            return Err(failure("TRUNCATED", at, 1));
        }
        let byte = reader.range(at, 1)?[0];
        value |= i64::from(byte & 0x7f) << (ordinal * 7);
        if byte & 0x80 == 0 {
            let bits = (ordinal + 1) * 7;
            if signed && byte & 0x40 != 0 {
                value -= 1i64 << bits;
            }
            let valid = if signed {
                i32::try_from(value).is_ok()
            } else {
                u32::try_from(value).is_ok()
            };
            if !valid {
                return Err(
                    failure("LEB_OVERFLOW", offset, ordinal + 1).detail("leb_profile", LEB_PROFILE)
                );
            }
            return Ok((value, ordinal + 1));
        }
    }
    Err(failure("LEB_OVERFLOW", offset, 5).detail("leb_profile", LEB_PROFILE))
}

pub fn read_uleb128(bytes: &[u8], offset: u64, end: u64) -> MddResult<(u32, u64)> {
    let (value, consumed) = leb(bytes, offset, end, false)?;
    Ok((value as u32, consumed))
}

pub fn read_sleb128(bytes: &[u8], offset: u64, end: u64) -> MddResult<(i32, u64)> {
    let (value, consumed) = leb(bytes, offset, end, true)?;
    Ok((value as i32, consumed))
}

/// Decode from the indicated raw MUTF-8 start to a bounded zero terminator.
/// The returned range excludes the length prefix and the terminator.
pub fn decode_mutf8(
    bytes: &[u8],
    offset: u64,
    end: u64,
    declared: u32,
    max_bytes: u64,
) -> MddResult<(DexText, u64)> {
    let reader = CheckedReader::new(bytes);
    if offset > end || end > reader.len() {
        return Err(failure("STRING_RANGE", offset, end.saturating_sub(offset)));
    }
    let mut at = offset;
    let mut units = Vec::new();
    loop {
        if at >= end {
            return Err(failure("TRUNCATED", at, 1));
        }
        let first = reader.range(at, 1)?[0];
        if first == 0 {
            if units.len() as u64 != u64::from(declared) {
                return Err(failure("STRING_LENGTH_MISMATCH", offset, at - offset)
                    .detail("declared_code_units", u64::from(declared))
                    .detail("observed_code_units", units.len().to_string()));
            }
            let raw = reader.range(offset, at - offset)?.to_vec();
            return Ok((
                DexText {
                    raw_mutf8: raw,
                    utf16_units: units,
                    declared_utf16_length: declared,
                    declared_length_verified: true,
                    raw_range: DexRange {
                        byte_offset: DecimalU64(offset),
                        byte_length: DecimalU64(at - offset),
                    },
                },
                at + 1,
            ));
        }
        let (width, value) = if first < 0x80 {
            (1, u16::from(first))
        } else if (0xc0..=0xdf).contains(&first) {
            if at + 2 > end {
                return Err(failure("TRUNCATED", at, 2));
            }
            let second = reader.range(at + 1, 1)?[0];
            if second & 0xc0 != 0x80 {
                return Err(failure("INVALID_MUTF8", at, 2));
            }
            let value = (u16::from(first & 31) << 6) | u16::from(second & 63);
            if value != 0 && value < 128 {
                return Err(failure("INVALID_MUTF8", at, 2));
            }
            (2, value)
        } else if (0xe0..=0xef).contains(&first) {
            if at + 3 > end {
                return Err(failure("TRUNCATED", at, 3));
            }
            let continuation = reader.range(at + 1, 2)?;
            if continuation.iter().any(|byte| byte & 0xc0 != 0x80) {
                return Err(failure("INVALID_MUTF8", at, 3));
            }
            let value = (u16::from(first & 15) << 12)
                | (u16::from(continuation[0] & 63) << 6)
                | u16::from(continuation[1] & 63);
            if value < 2048 {
                return Err(failure("INVALID_MUTF8", at, 3));
            }
            (3, value)
        } else {
            return Err(failure("INVALID_MUTF8", at, 1));
        };
        if at - offset + width > max_bytes {
            return Err(quota("STRING_BYTE_BUDGET", offset, at - offset + width));
        }
        if units.len() as u64 >= u64::from(declared) {
            return Err(failure(
                "STRING_LENGTH_MISMATCH",
                offset,
                at - offset + width,
            ));
        }
        units
            .try_reserve(1)
            .map_err(|_| quota("STRING_ALLOCATION_BUDGET", offset, at - offset + width))?;
        units.push(value);
        at += width;
    }
}

pub fn read_string_pool(
    bytes: &[u8],
    header: &DexHeader,
    limits: StringLimits,
) -> MddResult<Vec<DexString>> {
    let reader = CheckedReader::new(bytes);
    let table = header
        .tables
        .iter()
        .find(|table| table.name == "string_ids")
        .ok_or_else(|| failure("MISSING_STRING_TABLE", 56, 8))?;
    if table.count > limits.max_strings {
        return Err(quota(
            "STRING_COUNT_BUDGET",
            table.range.byte_offset.0,
            u64::from(table.count),
        ));
    }
    let section = header.map.iter().position(|item| item.type_code == 0x2002);
    if section.is_none() && table.count == 0 {
        return Ok(Vec::new());
    }
    let section_index = section.ok_or_else(|| failure("MISSING_STRING_DATA", 56, 8))?;
    let physical_count = header.map[section_index].count;
    if physical_count > limits.max_strings {
        return Err(quota(
            "STRING_COUNT_BUDGET",
            header.map[section_index].byte_offset.0,
            u64::from(physical_count),
        ));
    }
    let section_start = header.map[section_index].byte_offset.0;
    let section_end = header.map.get(section_index + 1).map_or(
        header.data_range.byte_offset.0 + header.data_range.byte_length.0,
        |item| item.byte_offset.0,
    );
    let mut references = Vec::new();
    references
        .try_reserve_exact(table.count as usize)
        .map_err(|_| quota("STRING_POOL_ALLOCATION_BUDGET", 56, 8))?;
    for string_idx in 0..table.count {
        let at = table.range.byte_offset.0 + u64::from(string_idx) * 4;
        let offset = u64::from(reader.u32(at)?);
        if offset < section_start || offset >= section_end {
            return Err(failure("STRING_OUTSIDE_SECTION", offset, 1));
        }
        references.push((offset, string_idx));
    }
    references.sort_unstable();
    if references.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(failure(
            "DUPLICATE_STRING_DATA_REFERENCE",
            table.range.byte_offset.0,
            table.range.byte_length.0,
        ));
    }
    let mut result: Vec<DexString> = Vec::new();
    result
        .try_reserve_exact(table.count as usize)
        .map_err(|_| quota("STRING_POOL_ALLOCATION_BUDGET", 56, 8))?;
    let mut total_units = 0u64;
    let mut physical_offset = section_start;
    let mut next_reference = 0usize;
    for physical_ordinal in 0..physical_count {
        let offset = physical_offset;
        if references
            .get(next_reference)
            .is_some_and(|reference| reference.0 < offset)
        {
            return Err(failure(
                "STRING_OFFSET_NOT_ITEM_START",
                references[next_reference].0,
                1,
            ));
        }
        let (declared, prefix) = read_uleb128(bytes, offset, section_end)?;
        total_units = total_units
            .checked_add(u64::from(declared))
            .ok_or_else(|| quota("STRING_TOTAL_BUDGET", offset, 1))?;
        if total_units > limits.max_total_code_units {
            return Err(quota("STRING_TOTAL_BUDGET", offset, u64::from(declared)));
        }
        let (text, next) = decode_mutf8(
            bytes,
            offset + prefix,
            section_end,
            declared,
            limits.max_string_bytes,
        )
        .map_err(|error| {
            error.detail("physical_string_data_ordinal", u64::from(physical_ordinal))
        })?;
        if let Some((_, string_idx)) = references
            .get(next_reference)
            .filter(|reference| reference.0 == offset)
        {
            result.push(DexString {
                string_idx: *string_idx,
                data_range: DexRange {
                    byte_offset: DecimalU64(offset),
                    byte_length: DecimalU64(next - offset),
                },
                text,
            });
            next_reference += 1;
        }
        physical_offset = next;
    }
    if next_reference != references.len() {
        return Err(failure(
            "STRING_OFFSET_NOT_ITEM_START",
            references[next_reference].0,
            1,
        ));
    }
    result.sort_unstable_by_key(|string| string.string_idx);
    for pair in result.windows(2) {
        if pair[0].text.utf16_units >= pair[1].text.utf16_units {
            return Err(failure(
                "STRING_IDS_NOT_STRICT_UTF16_ORDER",
                table.range.byte_offset.0 + u64::from(pair[1].string_idx) * 4,
                4,
            ));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate_header;
    use serde_json::Value;

    #[test]
    fn physical_string_item_starts_allow_orphans_and_reject_interior_offsets() {
        for data in [
            include_bytes!("../../../artifacts/integration/20261028/item-boundaries/valid-empty-string.dex").as_slice(),
            include_bytes!("../../../artifacts/integration/20261028/item-boundaries/valid-orphan-string-data.dex").as_slice(),
        ] {
            let header = validate_header(data).unwrap();
            let pool = read_string_pool(data, &header, StringLimits::default()).unwrap();
            assert_eq!(pool.len(), 1);
            assert!(pool[0].text.utf16_units.is_empty());
            assert_eq!(pool[0].data_range.byte_offset.0, 116);
        }
        let data = include_bytes!(
            "../../../artifacts/integration/20261028/item-boundaries/bad-interior-string.dex"
        );
        let header = validate_header(data).unwrap();
        let error = read_string_pool(data, &header, StringLimits::default()).unwrap_err();
        assert_eq!(error.details["reason"], "STRING_OFFSET_NOT_ITEM_START");
        assert_eq!(error.details["byte_offset"], "117");
    }

    fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digit = |byte: u8| {
                    if byte <= b'9' {
                        byte - b'0'
                    } else {
                        byte - b'a' + 10
                    }
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn independent_component_vectors_match_without_lossy_substitution() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/generated/component-vectors.json"
        ))
        .unwrap();
        for vector in vectors["mutf8"].as_array().unwrap() {
            let raw = bytes(vector["hex"].as_str().unwrap());
            let result = decode_mutf8(
                &raw,
                0,
                raw.len() as u64,
                vector["utf16_size"].as_u64().unwrap() as u32,
                1_000_000,
            );
            if let Some(reason) = vector["error"].as_str() {
                assert_eq!(
                    result.unwrap_err().details["reason"],
                    reason,
                    "{}",
                    vector["id"]
                );
            } else {
                let (text, next) = result.unwrap();
                assert_eq!(
                    serde_json::to_value(&text.utf16_units).unwrap(),
                    vector["expected_units"]
                );
                assert_eq!(next as usize, raw.len());
                assert_eq!(text.raw_mutf8, raw[..raw.len() - 1]);
                if text.utf16_units == [0xd800] || text.utf16_units == [0xdc00] {
                    assert!(text.strict_utf8().is_err());
                    assert_eq!(text.display_lossy(), "\u{fffd}");
                }
            }
        }
        for vector in vectors["leb32"].as_array().unwrap() {
            let raw = bytes(vector["hex"].as_str().unwrap());
            let result = if vector["kind"] == "sleb" {
                read_sleb128(&raw, 0, raw.len() as u64).map(|(value, n)| (i64::from(value), n))
            } else {
                read_uleb128(&raw, 0, raw.len() as u64).map(|(value, n)| (i64::from(value), n))
            };
            if let Some(reason) = vector["error"].as_str() {
                assert_eq!(
                    result.unwrap_err().details["reason"],
                    reason,
                    "{}",
                    vector["id"]
                );
            } else {
                assert_eq!(
                    result.unwrap(),
                    (vector["value"].as_i64().unwrap(), raw.len() as u64)
                );
            }
        }
    }

    #[test]
    fn all_512_independent_fifth_byte_oracle_cases_match() {
        let oracle: Value = serde_json::from_str(include_str!(
            "../../../artifacts/mdd-004/encoding-independent-review.json"
        ))
        .unwrap();
        for case in oracle["checks"].as_array().unwrap() {
            let raw = bytes(case["hex"].as_str().unwrap());
            let result = if case["signed"] == true {
                read_sleb128(&raw, 0, raw.len() as u64).map(|(value, n)| (i64::from(value), n))
            } else {
                read_uleb128(&raw, 0, raw.len() as u64).map(|(value, n)| (i64::from(value), n))
            };
            assert_eq!(result.is_ok(), case["expected_valid"].as_bool().unwrap());
            if let Ok((value, consumed)) = result {
                assert_eq!(value, case["observed"][0]["value"].as_i64().unwrap());
                assert_eq!(consumed, 5);
            }
        }
    }

    #[test]
    fn actual_pool_preserves_utf16_nul_and_surrogates() {
        let raw = include_bytes!("../../../tests/fixtures/generated/strings-mutf8-035.dex");
        let pool =
            read_string_pool(raw, &validate_header(raw).unwrap(), StringLimits::default()).unwrap();
        assert_eq!(
            pool.iter()
                .map(|item| item.text.utf16_units.clone())
                .collect::<Vec<_>>(),
            [
                vec![],
                vec![0],
                vec![65],
                vec![0x4e2d],
                vec![0xd800],
                vec![0xd83d, 0xde00],
                vec![0xdc00]
            ]
        );
        assert_eq!(pool[1].text.strict_utf8().unwrap(), "\0");
        assert_eq!(pool[5].text.strict_utf8().unwrap(), "\u{1f600}");
        assert!(pool[4].text.strict_utf8().is_err());
        assert!(
            read_string_pool(
                raw,
                &validate_header(raw).unwrap(),
                StringLimits {
                    max_strings: 0,
                    ..StringLimits::default()
                }
            )
            .is_err()
        );
    }
}
