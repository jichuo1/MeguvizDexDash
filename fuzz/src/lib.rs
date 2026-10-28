//! Test-only bounded targets. Panics are failures; malformed-input Results are expected.
use mdd_dex::{
    DexHeader, DexRange,
    annotations::{AnnotationLimits, read_annotations},
    definitions::{DefinitionLimits, DefinitionPools, read_definitions},
    instructions::{CodeLimits, DebugPolicy, read_code_section},
    strings::{StringLimits, decode_mutf8, read_sleb128, read_string_pool, read_uleb128},
    types::read_types_and_prototypes,
    validate_header,
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddResult};
use sha1::{Digest, Sha1};
use std::{cell::RefCell, fs, path::PathBuf, sync::OnceLock};

pub const MAX_INPUT: usize = 65_536;
pub const TARGETS: [&str; 6] = [
    "archive",
    "mutf8_leb",
    "header_raw",
    "header_repaired",
    "code_payload",
    "encoded_values",
];

#[derive(Default, Clone, Copy)]
pub struct Observation {
    pub accepted: u64,
    pub rejected: u64,
    pub header: u64,
    pub strings: u64,
    pub metadata: u64,
    pub code_items: u64,
    pub value_nodes: u64,
    pub archive_members: u64,
}
impl Observation {
    pub fn add(&mut self, other: Self) {
        self.accepted += other.accepted;
        self.rejected += other.rejected;
        self.header += other.header;
        self.strings += other.strings;
        self.metadata += other.metadata;
        self.code_items += other.code_items;
        self.value_nodes += other.value_nodes;
        self.archive_members += other.archive_members;
    }
}

fn result<T>(value: MddResult<T>, o: &mut Observation) -> Option<T> {
    match value {
        Ok(value) => {
            o.accepted += 1;
            Some(value)
        }
        Err(error) => {
            // A malformed input is ordinary; an internal fault is never successful fuzz work.
            assert_ne!(error.code, ErrorCode::InternalFault, "{error:?}");
            o.rejected += 1;
            None
        }
    }
}

pub fn range<'a>(bytes: &'a [u8], span: &DexRange) -> &'a [u8] {
    let start = usize::try_from(span.byte_offset.0).expect("range offset fits usize");
    let length = usize::try_from(span.byte_length.0).expect("range length fits usize");
    let end = start.checked_add(length).expect("range sum");
    assert!(
        end <= bytes.len(),
        "successful parser returned out-of-input range"
    );
    &bytes[start..end]
}

/// Repairs only file_size, SHA-1 and Adler32; no magic/map/table/semantic repair.
pub fn repair_checksums(data: &[u8]) -> Vec<u8> {
    let mut bytes = data.to_vec();
    if bytes.len() >= 112 {
        let size = u32::try_from(bytes.len()).expect("bounded input");
        bytes[32..36].copy_from_slice(&size.to_le_bytes());
        let signature = Sha1::digest(&bytes[32..]);
        bytes[12..32].copy_from_slice(&signature);
        let (mut a, mut b) = (1u32, 0u32);
        for byte in &bytes[12..] {
            a = (a + u32::from(*byte)) % 65521;
            b = (b + a) % 65521;
        }
        bytes[8..12].copy_from_slice(&((b << 16) | a).to_le_bytes());
    }
    bytes
}

fn header(bytes: &[u8], o: &mut Observation) -> Option<DexHeader> {
    let h = result(validate_header(bytes), o)?;
    assert_eq!(h.file_size.0, bytes.len() as u64);
    assert!(h.checksum_verified && h.signature_verified);
    assert!(!h.full_dex_validation_complete);
    range(bytes, &h.header_range);
    range(bytes, &h.data_range);
    for table in &h.tables {
        range(bytes, &table.range);
    }
    o.header += 1;
    Some(h)
}

fn header_tables(bytes: &[u8], h: &DexHeader, o: &mut Observation) {
    let Some(strings) = result(
        read_string_pool(
            bytes,
            h,
            StringLimits {
                max_strings: 1024,
                max_string_bytes: MAX_INPUT as u64,
                max_total_code_units: 32768,
            },
        ),
        o,
    ) else {
        return;
    };
    o.strings += strings.len() as u64;
    for item in &strings {
        assert_eq!(range(bytes, &item.text.raw_range), item.text.raw_mutf8);
        assert!(item.text.declared_length_verified);
    }
    if result(read_types_and_prototypes(bytes, h, &strings), o).is_some() {
        o.metadata += 1;
    }
}

fn reference_leb(data: &[u8], signed: bool) -> Option<(i64, u64)> {
    let mut value = 0i128;
    let mut multiplier = 1i128;
    for (index, byte) in data.iter().copied().take(5).enumerate() {
        value += i128::from(byte & 127) * multiplier;
        multiplier *= 128;
        if byte < 128 {
            if signed && byte & 64 != 0 {
                value -= multiplier;
            }
            let valid = if signed {
                (i32::MIN as i128..=i32::MAX as i128).contains(&value)
            } else {
                (0..=u32::MAX as i128).contains(&value)
            };
            return valid.then_some((value as i64, index as u64 + 1));
        }
    }
    None
}

fn mutf8_leb(data: &[u8], o: &mut Observation) {
    let u = read_uleb128(data, 0, data.len() as u64);
    assert_eq!(
        u.as_ref().ok().map(|(v, n)| (i64::from(*v), *n)),
        reference_leb(data, false)
    );
    result(u, o);
    let s = read_sleb128(data, 0, data.len() as u64);
    assert_eq!(
        s.as_ref().ok().map(|(v, n)| (i64::from(*v), *n)),
        reference_leb(data, true)
    );
    result(s, o);
    let Some((&declared, body)) = data.split_first() else {
        return;
    };
    if let Some((text, next)) = result(
        decode_mutf8(
            body,
            0,
            body.len() as u64,
            u32::from(declared),
            MAX_INPUT as u64,
        ),
        o,
    ) {
        assert_eq!(text.utf16_units.len(), usize::from(declared));
        assert_eq!(range(body, &text.raw_range), text.raw_mutf8);
        assert!(next > 0 && next <= body.len() as u64);
        assert_eq!(body[next as usize - 1], 0);
        // Independently re-encode preserved UTF-16 code units, including NUL/surrogates.
        let mut encoded = Vec::new();
        for unit in text.utf16_units {
            match unit {
                1..=127 => encoded.push(unit as u8),
                0..=2047 => {
                    encoded.extend([(0xc0 | (unit >> 6)) as u8, (0x80 | (unit & 63)) as u8])
                }
                _ => encoded.extend([
                    (0xe0 | (unit >> 12)) as u8,
                    (0x80 | ((unit >> 6) & 63)) as u8,
                    (0x80 | (unit & 63)) as u8,
                ]),
            }
        }
        assert_eq!(encoded, text.raw_mutf8);
    }
}

thread_local! { static SCRATCH: RefCell<Option<PathBuf>> = const { RefCell::new(None) }; }
static SCRATCH_ROOT: OnceLock<PathBuf> = OnceLock::new();
fn archive(data: &[u8], o: &mut Observation) {
    // Production capture currently has no from-bytes API. One private process-owned file
    // is reused; exact bytes are recaptured and its Arc snapshot is checked after parse.
    let root = SCRATCH_ROOT.get_or_init(|| {
        let path =
            std::env::temp_dir().join(mdd_types::opaque_id("mdd-fuzz").expect("scratch identity"));
        fs::create_dir(&path).expect("create isolated scratch");
        path
    });
    SCRATCH.with(|cell| {
        let mut cell = cell.borrow_mut();
        let path =
            cell.get_or_insert_with(|| root.join(format!("{:?}.zip", std::thread::current().id())));
        fs::write(&*path, data).expect("write controlled fuzz file");
        let Some(snapshot) = result(
            Snapshot::capture(
                &[InputSpec {
                    path: path.clone(),
                    kind: InputKind::Apk,
                    expected_sha256: None,
                }],
                CaptureLimits {
                    max_input_bytes: MAX_INPUT as u64,
                    max_sources: 1,
                },
            ),
            o,
        ) else {
            return;
        };
        let source = &snapshot.sources()[0];
        assert_eq!(source.bytes(), data);
        if let Some(inventory) = result(
            ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits {
                    max_members: 128,
                    max_directory_bytes: MAX_INPUT as u64,
                    max_member_bytes: MAX_INPUT as u64,
                    max_total_uncompressed_bytes: MAX_INPUT as u64 * 2,
                },
            ),
            o,
        ) {
            assert!(inventory.manifest().directory_complete);
            assert!(inventory.manifest().selected_dex_bytes_complete);
            o.archive_members += inventory.manifest().members.len() as u64;
            for dex in inventory.selected_dexes() {
                assert_eq!(dex.blob.content_id, mdd_types::content_id(dex.blob.bytes()));
                assert_eq!(&*dex.blob.lease(), dex.blob.bytes());
            }
        }
        assert_eq!(source.bytes(), data);
    });
}

pub fn run(target: &str, data: &[u8]) -> Observation {
    assert!(TARGETS.contains(&target), "unknown fuzz target");
    assert!(data.len() <= MAX_INPUT, "caller must enforce max_len");
    let mut o = Observation::default();
    if target == "archive" {
        archive(data, &mut o);
        return o;
    }
    if target == "mutf8_leb" {
        mutf8_leb(data, &mut o);
        return o;
    }
    let repaired;
    let bytes = if target == "header_raw" {
        data
    } else {
        repaired = repair_checksums(data);
        &repaired
    };
    let Some(h) = header(bytes, &mut o) else {
        return o;
    };
    match target {
        "header_raw" | "header_repaired" => header_tables(bytes, &h, &mut o),
        "code_payload" => {
            let limits = CodeLimits {
                debug_policy: DebugPolicy::EncodedFactsV1,
                max_code_items: 256,
                max_total_code_units: 32768,
                max_instructions: 32768,
                max_payload_elements: 8192,
                max_switch_targets: 8192,
                max_catch_pairs: 2048,
                max_debug_operations: 8192,
            };
            if let Some(code) = result(read_code_section(bytes, &h, limits), &mut o) {
                assert!(!code.full_dex_validation_complete);
                assert_eq!(code.items.len(), code.declared_code_item_count as usize);
                o.code_items += code.items.len() as u64;
                for item in code.items {
                    range(bytes, &item.raw_range);
                    range(bytes, &item.insns_range);
                    for instruction in item.instructions {
                        range(bytes, &instruction.raw_range);
                    }
                    for payload in item.payloads {
                        range(bytes, &payload.raw_range);
                    }
                    if let Some(debug) = item.debug_info {
                        range(bytes, &debug.raw_range);
                    }
                }
            }
        }
        "encoded_values" => {
            let Some(strings) = result(
                read_string_pool(
                    bytes,
                    &h,
                    StringLimits {
                        max_strings: 1024,
                        max_string_bytes: 65536,
                        max_total_code_units: 32768,
                    },
                ),
                &mut o,
            ) else {
                return o;
            };
            let Some((types, prototypes)) =
                result(read_types_and_prototypes(bytes, &h, &strings), &mut o)
            else {
                return o;
            };
            let pools = DefinitionPools {
                strings: &strings,
                types: &types,
                prototypes: &prototypes,
            };
            let Some(defs) = result(
                read_definitions(
                    bytes,
                    &h,
                    &pools,
                    DefinitionLimits {
                        max_rows: 4096,
                        max_text_bytes: 262144,
                    },
                ),
                &mut o,
            ) else {
                return o;
            };
            if let Some(values) = result(
                read_annotations(
                    bytes,
                    &h,
                    &pools,
                    &defs,
                    AnnotationLimits {
                        max_depth: 16,
                        max_items: 1024,
                        max_nodes: 4096,
                        max_rows: 8192,
                        max_decoded_bytes: 262144,
                    },
                ),
                &mut o,
            ) {
                o.value_nodes += values.values.len() as u64;
                for value in values.values {
                    range(bytes, &value.encoded_range);
                }
            }
        }
        _ => panic!("unknown fuzz target: {target}"),
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_rejection_and_repaired_internal_path_are_distinct() {
        let original = include_bytes!("../../tests/fixtures/generated/minimal-035.dex");
        assert_eq!(run("header_raw", original).header, 1);
        let mut bad = original.to_vec();
        bad[8] ^= 1;
        let error = validate_header(&bad).expect_err("invalid checksum must not succeed");
        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert_eq!(run("header_raw", &bad).header, 0);
        assert_eq!(run("header_repaired", &bad).header, 1);
        // Fixing hashes must not forgive structural header damage.
        bad[36] ^= 1;
        assert_eq!(run("header_repaired", &bad).header, 0);
    }

    #[test]
    fn narrow_seeds_reach_code_and_encoded_values() {
        let code = include_bytes!("../../tests/fixtures/instructions/generated/packed-switch.dex");
        assert!(run("code_payload", code).code_items > 0);
        let values =
            include_bytes!("../../tests/fixtures/annotations/generated/annotations-038.dex");
        assert!(run("encoded_values", values).value_nodes > 0);
        // NUL, surrogate and signed/unsigned fifth-byte boundaries use independent re-encoding/LEB arithmetic.
        for bytes in [
            &b"\x01\xc0\x80\x00"[..],
            &b"\x01\xed\xa0\x80\x00"[..],
            &b"\xff\xff\xff\xff\x0f"[..],
            &b"\xff\xff\xff\xff\x7f"[..],
        ] {
            run("mutf8_leb", bytes);
        }
    }
}
