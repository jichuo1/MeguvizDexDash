//! Replay the fixed reference CAST statements over the same synthetic inputs.
use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy}, snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot}};
use mdd_sql::{SqlBridge, control::SqlLimits, dialects::SqlDialect, provider::metadata::MetadataSqlProvider};
use mdd_types::{DecimalU64, MddResult};
use std::{path::PathBuf, sync::Arc};

fn provider(path: PathBuf, sha: &str) -> MddResult<Arc<MetadataSqlProvider>> {
    let snapshot = Snapshot::capture(&[InputSpec {path, kind:InputKind::RawDex, expected_sha256:Some(sha.into())}], CaptureLimits::default())?;
    let inventory = ArchiveInventory::build(&snapshot.sources()[0], InventoryPolicy::default(), ArchiveLimits::default())?;
    let facts = Arc::new(MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default())?);
    Ok(Arc::new(MetadataSqlProvider::new(vec![facts], DecimalU64(0))?))
}
fn run() -> MddResult<serde_json::Value> {
    let root = PathBuf::from(std::env::args_os().nth(1).expect("workspace root"));
    let literals = provider(root.join("tests/fixtures/references/generated/classic-035.dex"), "076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8")?;
    let dex = provider(root.join("tests/fixtures/generated/strings-mutf8-035.dex"), "4deab5f75b23c118b170005d89a6ebc0d18d894383280253e70de0507d260f35")?;
    let cases = [
        ("empty", "SELECT CAST('' AS INTEGER) AS v"), ("invalid", "SELECT CAST('bad' AS INTEGER) AS v"),
        ("prefix", "SELECT CAST('  +00012tail' AS INTEGER) AS v"), ("negative_decimal", "SELECT CAST('-5.9' AS INTEGER) AS v"),
        ("leading_decimal", "SELECT CAST('.5' AS INTEGER) AS v"), ("exponent", "SELECT CAST('1e5' AS INTEGER) AS v"),
        ("hex_text", "SELECT CAST('0x10' AS INTEGER) AS v"), ("double_sign", "SELECT CAST('++1' AS INTEGER) AS v"),
        ("whitespace", "SELECT CAST('\t-12\n' AS INTEGER) AS v"), ("nul_after_digits", "SELECT CAST('+12\0Z' AS INTEGER) AS v"),
        ("nul_before_digits", "SELECT CAST('\0-12' AS INTEGER) AS v"), ("max", "SELECT CAST('9223372036854775807' AS INTEGER) AS v"),
        ("above_max", "SELECT CAST('9223372036854775808' AS INTEGER) AS v"), ("below_min", "SELECT CAST('-9223372036854775809' AS INTEGER) AS v"),
        ("oversized", "SELECT CAST('999999999999999999999999999999999999' AS INTEGER) AS v"), ("min", "SELECT CAST('-9223372036854775808' AS INTEGER) AS v"),
        ("blob_prefix", "SELECT CAST(X'31327461696C' AS INTEGER) AS v"), ("blob_nul", "SELECT CAST(X'31320039' AS INTEGER) AS v"),
        ("blob_invalid", "SELECT CAST(X'FF3132' AS INTEGER) AS v"), ("null", "SELECT CAST(NULL AS INTEGER) AS v"),
    ];
    let mut observations = Vec::new();
    for (name, dialect) in [("010",SqlDialect::DexSql010),("011",SqlDialect::DexSql011)] {
        let literal_bridge = SqlBridge::new(literals.clone(), dialect, SqlLimits::default())?;
        let dex_bridge = SqlBridge::new(dex.clone(), dialect, SqlLimits::default())?;
        let mut values = Vec::new();
        for (id, sql) in cases { values.push(serde_json::json!({"id":id, "sql":sql, "result":literal_bridge.query(sql)?})); }
        let mut dex_values = Vec::new();
        for i in 0..7 {
            let sql = format!("SELECT CAST(value AS INTEGER) AS v FROM native_strings WHERE string_idx={i}");
            dex_values.push(serde_json::json!({"id":format!("string_{i}"), "sql":sql, "result":dex_bridge.query(&sql)?}));
        }
        observations.push(serde_json::json!({"dialect":name,"literal_cases":values,"dex_cases":dex_values}));
    }
    Ok(serde_json::json!({"probe_complete":true,"dialects":observations,"profile_admitted":false}))
}
fn main() { match run() { Ok(value) => println!("{value}"), Err(error) => { eprintln!("{}",serde_json::json!({"probe_complete":false,"error":error})); std::process::exit(1); } } }
