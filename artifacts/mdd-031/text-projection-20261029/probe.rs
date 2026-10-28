//! Tiny, synthetic DEX and structured-parameter SQL observation.
use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy}, snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot}};
use mdd_sql::{SqlBridge, control::{SqlControl, SqlLimits}, dialects::SqlDialect, provider::metadata::MetadataSqlProvider, values::{SqlText, SqlValue}};
use mdd_types::{DecimalU64, MddResult};
use std::{path::PathBuf, sync::Arc};

fn run() -> MddResult<serde_json::Value> {
    let path = PathBuf::from(std::env::args_os().nth(1).expect("fixture path"));
    let snapshot = Snapshot::capture(&[InputSpec { path, kind: InputKind::RawDex,
        expected_sha256: Some("4deab5f75b23c118b170005d89a6ebc0d18d894383280253e70de0507d260f35".into()) }], CaptureLimits::default())?;
    let inventory = ArchiveInventory::build(&snapshot.sources()[0], InventoryPolicy::default(), ArchiveLimits::default())?;
    let facts = Arc::new(MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default())?);
    let provider = Arc::new(MetadataSqlProvider::new(vec![facts], DecimalU64(0))?);
    let vectors: &[(&str, &[u16], &[u8])] = &[
        ("empty", &[], &[]), ("nul", &[0], &[0xc0, 0x80]),
        ("ascii", &[0x41], &[0x41]), ("cjk", &[0x4e2d], &[0xe4, 0xb8, 0xad]),
        ("high", &[0xd800], &[0xed, 0xa0, 0x80]),
        ("supplementary", &[0xd83d, 0xde00], &[0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]),
        ("low", &[0xdc00], &[0xed, 0xb0, 0x80]),
    ];
    let mut results = Vec::new();
    for (name, dialect) in [("native", SqlDialect::NativeV1), ("010", SqlDialect::DexSql010), ("011", SqlDialect::DexSql011)] {
        let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default())?;
        let source = bridge.query("SELECT string_idx,value,raw_mutf8,hex(raw_mutf8) AS raw_hex,hex(CAST(value AS TEXT)) AS text_hex FROM native_strings ORDER BY string_idx")?;
        let mut params = Vec::new();
        for (label, units, raw) in vectors {
            let text = SqlValue::Text(SqlText { utf16: units.to_vec(), original_mutf8: Some(raw.to_vec()) });
            let values = vec![text.clone(), text, SqlValue::DexMutf8 { bytes: raw.to_vec(), utf16_code_units: DecimalU64(units.len() as u64) }];
            let prepared = bridge.prepare_with_parameters("SELECT CAST(? AS TEXT) AS value,hex(CAST(? AS TEXT)) AS text_hex,hex(?) AS raw_hex", &values)?;
            let result = prepared.execute(SqlControl::new(SqlLimits::default(), None))?;
            params.push(serde_json::json!({"case":label,"result":result}));
        }
        let null_result = bridge.query("SELECT NULL AS v,hex(CAST(NULL AS TEXT)) AS h")?;
        results.push(serde_json::json!({"dialect":name,"source_query":source,"parameters":params,"null_query":null_result}));
    }
    Ok(serde_json::json!({"probe_complete":true,"fixture_sha256":"4deab5f75b23c118b170005d89a6ebc0d18d894383280253e70de0507d260f35","snapshot_id":snapshot.manifest().snapshot_id,"dialects":results,"profile_admitted":false}))
}
fn main() {
    match run() { Ok(value) => println!("{value}"), Err(error) => { eprintln!("{}", serde_json::json!({"probe_complete":false,"error":error})); std::process::exit(1); } }
}
