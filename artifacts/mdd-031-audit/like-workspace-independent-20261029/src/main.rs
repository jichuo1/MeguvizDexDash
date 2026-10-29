use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot}};
use mdd_query::budget::{BudgetLimits, BudgetPool, BudgetScope, Resource, RuntimeBudget};
use mdd_session::{Lifecycle, ResourceLimits, SessionHandle, cancellation::QueryCancellation};
use mdd_sql::{SqlBridge, PreparedSql, control::{SqlControl, SqlLimits}, dialects::SqlDialect,
    provider::metadata::MetadataSqlProvider, values::SqlValue};
use mdd_types::DecimalU64;
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc, time::{Duration, Instant}};

fn setup() -> (Lifecycle, SessionHandle, SqlBridge) {
    let path = PathBuf::from("tests/fixtures/references/generated/classic-035.dex");
    let snapshot = Arc::new(Snapshot::capture(&[InputSpec { path, kind: InputKind::RawDex,
        expected_sha256: Some("076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8".into()) }],
        CaptureLimits::default()).unwrap());
    let inventory = ArchiveInventory::build(&snapshot.sources()[0], InventoryPolicy::default(), ArchiveLimits::default()).unwrap();
    let facts = Arc::new(MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap());
    let provider = Arc::new(MetadataSqlProvider::new(vec![facts], DecimalU64(0)).unwrap());
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
    let snapshot_handle = lifecycle.register_snapshot(snapshot).unwrap();
    let session = lifecycle.open_session(&snapshot_handle, ResourceLimits::default()).unwrap();
    (lifecycle, session, bridge)
}

fn runtime(lifecycle: &Lifecycle, session: &SessionHandle, prepared: &PreparedSql, bytes: u64) -> (RuntimeBudget, QueryCancellation) {
    let query = lifecycle.prepare_query(session, prepared.runtime_query_binding().unwrap(), ResourceLimits::default()).unwrap();
    lifecycle.start_query(session, &query, 1).unwrap();
    let token = lifecycle.cancellation_token(&query).unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, bytes);
    let root = BudgetPool::global("like-independent-root".into(), limits.clone()).unwrap();
    let worker = root.child(token.worker_owner_id().unwrap(), BudgetScope::Worker, limits.clone()).unwrap();
    let session_pool = worker.child(session.id().into(), BudgetScope::Session, limits.clone()).unwrap();
    let query_pool = session_pool.child(query.id().into(), BudgetScope::Query, limits).unwrap();
    (RuntimeBudget::new(query_pool, token.clone()).unwrap(), token)
}

fn used(pool: &BudgetPool) -> u64 {
    pool.usage().unwrap().used.get(&Resource::QueryWorkspaceBytes).map_or(0, |v| v.0)
}

fn run_case(name: &str, bytes: u64, units: usize, mode: &str) -> Value {
    let (lifecycle, session, bridge) = setup();
    let pattern = SqlValue::text(&"%".repeat(units));
    let prepared = bridge.prepare_with_parameters("SELECT '' LIKE ? AS value", &[pattern]).unwrap();
    let (runtime, token) = runtime(&lifecycle, &session, &prepared, bytes);
    let pool = runtime.pool().clone();
    let bound = prepared.bind_runtime(&runtime).unwrap();
    if mode == "during" {
        let task = std::thread::spawn(move || bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime)));
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut observed = 0;
        loop {
            let current = used(&pool);
            if current > 100_000 { observed = current; break; }
            if task.is_finished() || Instant::now() >= deadline { break; }
            std::thread::yield_now();
        }
        token.cancel().unwrap();
        let result = task.join().unwrap();
        return json!({"case":name,"observed_token_reservation":observed,"result": match result {
            Ok(x) => json!({"status":"ok","rows":x.rows()}), Err(e) => json!({"status":"error","error":e})},
            "used_after":used(&pool),"execution_complete":token.status().unwrap().execution_complete});
    }
    if mode == "before" { token.cancel().unwrap(); }
    let result = bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime));
    match result {
        Ok(result) => {
            let held = used(&pool);
            let rows = serde_json::to_value(result.rows()).unwrap();
            let complete = result.calculation_complete();
            drop(result);
            json!({"case":name,"status":"ok","rows":rows,"calculation_complete":complete,
                "used_with_result":held,"used_after_drop":used(&pool),"execution_complete":token.status().unwrap().execution_complete})
        }
        Err(error) => json!({"case":name,"status":"error","error":error,"used_after":used(&pool),
            "execution_complete":token.status().unwrap().execution_complete}),
    }
}

fn main() {
    let records = vec![run_case("low", 8192, 10_000, "normal"),
        run_case("sufficient", 65_536, 10_000, "normal"),
        run_case("cancel_before", 65_536, 10_000, "before"),
        run_case("cancel_while_reserved", 4 * 1024 * 1024, 300_000, "during")];
    println!("{}", json!({"records":records,"scope":"real snapshot/session/runtime budget, synthetic single input; no SQLite RSS or transport proof","profile_admitted":false}));
}
