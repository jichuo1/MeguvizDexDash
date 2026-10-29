use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot}};
use mdd_query::budget::{BudgetLimits, BudgetPool, BudgetScope, Resource, RuntimeBudget};
use mdd_session::{Lifecycle, ResourceLimits};
use mdd_sql::{SqlBridge, control::{SqlControl, SqlLimits}, dialects::SqlDialect,
    provider::metadata::MetadataSqlProvider, values::SqlValue};
use mdd_types::DecimalU64;
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};

fn run(case: &str, sql: &str, args: &[SqlValue]) -> Value {
    let snapshot = Arc::new(Snapshot::capture(&[InputSpec {
        path: PathBuf::from("tests/fixtures/references/generated/classic-035.dex"), kind: InputKind::RawDex,
        expected_sha256: Some("076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8".into()),
    }], CaptureLimits::default()).unwrap());
    let inventory = ArchiveInventory::build(&snapshot.sources()[0], InventoryPolicy::default(), ArchiveLimits::default()).unwrap();
    let facts = Arc::new(MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap());
    let provider = Arc::new(MetadataSqlProvider::new(vec![facts], DecimalU64(0)).unwrap());
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let prepared = bridge.prepare_with_parameters(sql, args).unwrap();
    let life = Lifecycle::new(ResourceLimits::default()).unwrap();
    let snap = life.register_snapshot(snapshot).unwrap();
    let session = life.open_session(&snap, ResourceLimits::default()).unwrap();
    let query = life.prepare_query(&session, prepared.runtime_query_binding().unwrap(), ResourceLimits::default()).unwrap();
    life.start_query(&session, &query, 1).unwrap();
    let token = life.cancellation_token(&query).unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 65_536);
    let root = BudgetPool::global("like-extras-root".into(), limits.clone()).unwrap();
    let worker = root.child(token.worker_owner_id().unwrap(), BudgetScope::Worker, limits.clone()).unwrap();
    let session_pool = worker.child(session.id().into(), BudgetScope::Session, limits.clone()).unwrap();
    let pool = session_pool.child(query.id().into(), BudgetScope::Query, limits).unwrap();
    let runtime = RuntimeBudget::new(pool.clone(), token.clone()).unwrap();
    let bound = prepared.bind_runtime(&runtime).unwrap();
    let used = || pool.usage().unwrap().used.get(&Resource::QueryWorkspaceBytes).map_or(0, |v| v.0);
    let result = bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime));
    match result {
        Ok(value) => {
            let rows = serde_json::to_value(value.rows()).unwrap();
            let held = used();
            drop(value);
            json!({"case":case,"status":"ok","rows":rows,"held":held,"after":used(),
                "execution_complete":token.status().unwrap().execution_complete})
        }
        Err(error) => json!({"case":case,"status":"error","error":error,"after":used(),
            "execution_complete":token.status().unwrap().execution_complete}),
    }
}

fn main() {
    let long_dangling = SqlValue::text(&format!("{}\\", "%".repeat(10_000)));
    let records = vec![
        run("dangling_escape", "SELECT '' LIKE ? ESCAPE ? AS value", &[long_dangling, SqlValue::text("\\")]),
        run("null_value", "SELECT ? LIKE ? AS value", &[SqlValue::Null, SqlValue::text("%")]),
        run("escaped_percent", "SELECT ? LIKE ? ESCAPE ? AS value", &[SqlValue::text("a%b"), SqlValue::text("a\\%b"), SqlValue::text("\\")]),
    ];
    println!("{}",json!({"records":records,"profile_admitted":false,"scope":"synthetic real snapshot/session; current bridge only; old escape semantics not checked"}));
}
