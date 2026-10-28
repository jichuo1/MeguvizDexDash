use crate::{
    SqlBridge,
    control::{SqlControl, SqlLimits},
    dialects::SqlDialect,
    provider::metadata::MetadataSqlProvider,
};
use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_query::budget::{BudgetLimits, BudgetPool, BudgetScope, Resource, RuntimeBudget};
use mdd_session::{Lifecycle, ResourceLimits, SessionHandle, cancellation::QueryCancellation};
use mdd_types::{DecimalU64, ErrorCode};
use std::{path::PathBuf, sync::Arc};

fn setup() -> (Lifecycle, SessionHandle, SessionHandle, SqlBridge) {
    let snapshot = Arc::new(
        Snapshot::capture(
            &[InputSpec {
                path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/references/generated/nonscalar-string-035.dex"),
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap(),
    );
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let facts =
        Arc::new(MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap());
    let provider = Arc::new(MetadataSqlProvider::new(vec![facts], DecimalU64(0)).unwrap());
    let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
    let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
    let snapshot_handle = lifecycle.register_snapshot(snapshot).unwrap();
    let a = lifecycle
        .open_session(&snapshot_handle, ResourceLimits::default())
        .unwrap();
    let b = lifecycle
        .open_session(&snapshot_handle, ResourceLimits::default())
        .unwrap();
    (lifecycle, a, b, bridge)
}

fn runtime(
    lifecycle: &Lifecycle,
    session: &SessionHandle,
    prepared: &crate::PreparedSql,
    limits: BudgetLimits,
) -> (RuntimeBudget, QueryCancellation) {
    let query = lifecycle
        .prepare_query(
            session,
            prepared.runtime_query_binding().unwrap(),
            ResourceLimits::default(),
        )
        .unwrap();
    lifecycle.start_query(session, &query, 1).unwrap();
    let token = lifecycle.cancellation_token(&query).unwrap();
    let global = BudgetPool::global("sql-test-root".into(), limits.clone()).unwrap();
    let worker = global
        .child(
            token.worker_owner_id().unwrap(),
            BudgetScope::Worker,
            limits.clone(),
        )
        .unwrap();
    let session_budget = worker
        .child(session.id().into(), BudgetScope::Session, limits.clone())
        .unwrap();
    let query_budget = session_budget
        .child(query.id().into(), BudgetScope::Query, limits)
        .unwrap();
    (
        RuntimeBudget::new(query_budget, token.clone()).unwrap(),
        token,
    )
}

#[test]
fn same_snapshot_other_session_is_rejected_without_claiming_either_query() {
    let (lifecycle, a, b, bridge) = setup();
    let prepared = bridge.prepare("SELECT value FROM native_strings").unwrap();
    let (runtime_a, token_a) = runtime(&lifecycle, &a, &prepared, BudgetLimits::default());
    let (runtime_b, token_b) = runtime(&lifecycle, &b, &prepared, BudgetLimits::default());
    let bound = prepared.bind_runtime(&runtime_a).unwrap();
    let bad = SqlControl::new(SqlLimits::default(), None).with_runtime(runtime_b);
    assert_eq!(
        bound.execute(bad).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert!(token_b.status().unwrap().error.is_none());
    let good = SqlControl::new(SqlLimits::default(), None).with_runtime(runtime_a);
    let result = bound.execute(good).unwrap();
    assert!(!result.rows().is_empty());
    assert!(result.calculation_complete());
    assert!(token_a.status().unwrap().execution_complete);
    assert!(!token_a.status().unwrap().delivery_complete);
    token_b.claim_execution().unwrap();
}

#[test]
fn shared_work_budget_stops_real_metadata_before_owned_result_and_is_sticky() {
    let (lifecycle, session, _, bridge) = setup();
    let prepared = bridge.prepare("SELECT value FROM native_strings").unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkBytes, 0);
    let (limited_runtime, token) = runtime(&lifecycle, &session, &prepared, limits);
    let bound = prepared.bind_runtime(&limited_runtime).unwrap();
    let control = SqlControl::new(SqlLimits::default(), None).with_runtime(limited_runtime);
    assert_eq!(
        bound.execute(control).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    let status = token.status().unwrap();
    assert_eq!(status.error.unwrap().code, ErrorCode::QuotaExceeded);
    assert!(!status.execution_complete);
    assert!(!status.delivery_complete);
}

#[test]
fn typed_numeric_truth_preserves_sql_three_valued_conditions() {
    let (_, _, _, bridge) = setup();
    let output = bridge.query("SELECT CASE WHEN CAST(1 AS UNSIGNED) THEN 1 ELSE 0 END, CAST(1 AS UNSIGNED) IS TRUE, NOT CAST(1 AS UNSIGNED), CAST(1 AS UNSIGNED) AND 1, CAST(1 AS UNSIGNED) OR 0, NULL AND CAST(1 AS UNSIGNED), NULL OR CAST(1 AS UNSIGNED)").unwrap();
    use crate::values::SqlValue;
    use mdd_query::ir::Signed64;
    let int = |n| SqlValue::I64(Signed64(n));
    assert_eq!(
        output.rows()[0],
        vec![
            int(1),
            int(1),
            int(0),
            int(1),
            int(1),
            SqlValue::Null,
            int(1)
        ]
    );
    assert_eq!(
        bridge
            .query("SELECT 1 WHERE CAST(1 AS UNSIGNED)")
            .unwrap()
            .rows()
            .len(),
        1
    );
    assert_eq!(
        bridge
            .query("SELECT 1 WHERE CAST(0 AS UNSIGNED)")
            .unwrap()
            .rows()
            .len(),
        0
    );
}

#[test]
fn result_workspace_is_admitted_before_delivery_and_retained_until_drop() {
    let (lifecycle, session, _, bridge) = setup();
    let prepared = bridge.prepare("SELECT value FROM native_strings").unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 1);
    let (limited_runtime, token) = runtime(&lifecycle, &session, &prepared, limits);
    let limited_pool = limited_runtime.pool().clone();
    let bound = prepared.bind_runtime(&limited_runtime).unwrap();
    let control = SqlControl::new(SqlLimits::default(), None).with_runtime(limited_runtime);
    assert_eq!(
        bound.execute(control).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    assert!(!token.status().unwrap().execution_complete);
    assert_eq!(
        limited_pool
            .usage()
            .unwrap()
            .used
            .get(&Resource::QueryWorkspaceBytes)
            .map_or(0, |value| value.0),
        0
    );

    let prepared = bridge.prepare("SELECT value FROM native_strings").unwrap();
    let (runtime, token) = runtime(&lifecycle, &session, &prepared, BudgetLimits::default());
    let pool = runtime.pool().clone();
    let bound = prepared.bind_runtime(&runtime).unwrap();
    let control = SqlControl::new(SqlLimits::default(), None).with_runtime(runtime);
    let result = bound.execute(control).unwrap();
    assert!(!result.rows().is_empty());
    let serialized = serde_json::to_value(&result).unwrap();
    assert!(serialized.get("rows").unwrap().is_array());
    assert!(serialized.get("_result_memory").is_none());
    assert!(pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0 > 0);
    assert!(token.status().unwrap().execution_complete);
    assert!(!token.status().unwrap().delivery_complete);
    drop(result);
    assert_eq!(
        pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0,
        0
    );
}

#[test]
fn small_exact_workspace_does_not_require_a_full_reservation_chunk() {
    let (lifecycle, session, _, bridge) = setup();
    let prepared = bridge.prepare("SELECT 'a'").unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 3000);
    let (runtime, _) = runtime(&lifecycle, &session, &prepared, limits);
    let pool = runtime.pool().clone();
    let bound = prepared.bind_runtime(&runtime).unwrap();
    let result = bound
        .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
        .unwrap();
    assert_eq!(result.rows().len(), 1);
    let used = pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0;
    assert!((1..=3000).contains(&used));
    drop(result);
    assert_eq!(
        pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0,
        0
    );
}

#[test]
fn zero_rows_still_reserve_result_schema_and_identity() {
    let (lifecycle, session, _, bridge) = setup();
    let prepared = bridge.prepare("SELECT 1 AS long_alias WHERE 0").unwrap();
    let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 0);
    let (limited, token) = runtime(&lifecycle, &session, &prepared, limits);
    let bound = prepared.bind_runtime(&limited).unwrap();
    let result = bound.execute(SqlControl::new(SqlLimits::default(), None).with_runtime(limited));
    assert_eq!(result.unwrap_err().code, ErrorCode::QuotaExceeded);
    assert!(!token.status().unwrap().execution_complete);

    let prepared = bridge.prepare("SELECT 1 AS long_alias WHERE 0").unwrap();
    let (runtime, _) = runtime(&lifecycle, &session, &prepared, BudgetLimits::default());
    let pool = runtime.pool().clone();
    let bound = prepared.bind_runtime(&runtime).unwrap();
    let result = bound
        .execute(SqlControl::new(SqlLimits::default(), None).with_runtime(runtime))
        .unwrap();
    assert!(result.rows().is_empty());
    assert_eq!(result.columns(), &["long_alias"]);
    assert!(pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0 > 0);
    drop(result);
    assert_eq!(
        pool.usage().unwrap().used[&Resource::QueryWorkspaceBytes].0,
        0
    );
}
