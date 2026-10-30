//! Owned subprocess conformance tool, intentionally restricted to a tiny DEX.
use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_sql::{
    SqlBridge, control::SqlLimits, dialects::SqlDialect, provider::metadata::MetadataSqlProvider,
};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use std::{path::PathBuf, process::ExitCode, sync::Arc};

fn run() -> MddResult<serde_json::Value> {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or_else(|| MddError::new(ErrorCode::InvalidArgument, "probe", "MODE required"))?;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/references/generated/classic-035.dex");
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: Some(
                "076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8".into(),
            ),
        }],
        CaptureLimits::default(),
    )?;
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )?;
    let facts = Arc::new(MetadataFacts::build(
        &snapshot,
        &inventory,
        0,
        StringLimits::default(),
    )?);
    let provider = Arc::new(MetadataSqlProvider::new(vec![facts], DecimalU64(0))?);
    let dialect = match args.next().as_deref() {
        Some("010") => SqlDialect::DexSql010,
        Some("011") => SqlDialect::DexSql011,
        Some("native") => SqlDialect::NativeV1,
        _ => {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "probe",
                "dialect native/010/011 required",
            ));
        }
    };
    let bridge = SqlBridge::new(provider, dialect, SqlLimits::default())?;
    if mode == "stress" {
        let case = args.next().ok_or_else(|| {
            MddError::new(ErrorCode::InvalidArgument, "probe", "stress case required")
        })?;
        let sql = match case.as_str() {
            "binary" => "SELECT 1".to_owned() + &"+1".repeat(10000),
            "union" => "SELECT 1".to_owned() + &" UNION ALL SELECT 1".repeat(5000),
            "nested" => "SELECT ".to_owned() + &"(".repeat(5000) + "1" + &")".repeat(5000),
            _ => {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "probe",
                    "unknown stress case",
                ));
            }
        };
        return match bridge.prepare(&sql) {
            Ok(_) => Err(MddError::new(
                ErrorCode::InternalFault,
                "probe",
                "hostile SQL unexpectedly admitted",
            )),
            Err(error) if error.code == ErrorCode::QuotaExceeded => Ok(
                serde_json::json!({"operation_status":"expected_error","process_survived":true,"input_sql_bytes":sql.len(),"error":error,"profile_admitted":false}),
            ),
            Err(error) => Err(error),
        };
    }
    if mode != "query" {
        return Err(MddError::new(
            ErrorCode::InvalidArgument,
            "probe",
            "unknown mode",
        ));
    }
    let sql = args
        .next()
        .ok_or_else(|| MddError::new(ErrorCode::InvalidArgument, "probe", "SQL required"))?;
    let output = bridge.query(&sql)?;
    Ok(serde_json::json!({"operation_status":"ok","result":output,"full_audit_complete":false}))
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
                serde_json::json!({"operation_status":"error","error":error,"full_audit_complete":false})
            );
            ExitCode::FAILURE
        }
    }
}
