use super::*;
use crate::{
    budget::{BudgetLimits, BudgetPool, BudgetScope, RuntimeBudget},
    executor::facts::{MemoryCatalog, Table},
};
use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
use mdd_session::{Lifecycle, ResourceLimits, SessionHandle, cancellation::QueryCancellation};
use mdd_types::{
    Completeness, Coverage, OperationStatus,
    result::{ResultIdentity, StreamVerifier, TerminalBuilder},
};
use std::{path::PathBuf, sync::Arc};

struct Fixture {
    lifecycle: Lifecycle,
    session: SessionHandle,
    source: MemoryCatalog,
    prepared: PreparedQuery,
    cancel: QueryCancellation,
    runtime: RuntimeBudget,
}
fn setup(limits: BudgetLimits) -> Fixture {
    let snapshot = Arc::new(
        Snapshot::capture(
            &[InputSpec {
                path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/generated/minimal-035.dex"),
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap(),
    );
    let snapshot_id = snapshot.manifest().snapshot_id.clone();
    let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
    let handle = lifecycle.register_snapshot(snapshot).unwrap();
    let session = lifecycle
        .open_session(&handle, ResourceLimits::default())
        .unwrap();
    let source = MemoryCatalog::new(
        snapshot_id.clone(),
        DecimalU64(0),
        BTreeMap::from([(
            "rows".into(),
            Table {
                columns: vec![Column {
                    id: "n".into(),
                    display_name: "n".into(),
                    data_type: DataType::U64,
                    nullable: false,
                }],
                required_layers: vec![FactLayer::Structure],
                rows: (0..4).map(|n| vec![Value::U64(DecimalU64(n))]).collect(),
            },
        )]),
        BTreeSet::from([FactLayer::Structure]),
    )
    .unwrap();
    let prepared = prepare(
        QueryIr {
            schema_version: IR_VERSION.into(),
            text_semantics: TEXT_VERSION.into(),
            snapshot_id,
            catalog_epoch: DecimalU64(0),
            require_stable_order: false,
            root: Node::Scan {
                relation: "rows".into(),
            },
        },
        &source,
    )
    .unwrap();
    let query = lifecycle
        .prepare_query(
            &session,
            prepared.runtime_binding().unwrap(),
            ResourceLimits::default(),
        )
        .unwrap();
    lifecycle.start_query(&session, &query, 1).unwrap();
    let cancel = lifecycle.cancellation_token(&query).unwrap();
    let global = BudgetPool::global("g".into(), limits.clone()).unwrap();
    let worker = global
        .child(
            cancel.worker_owner_id().unwrap(),
            BudgetScope::Worker,
            limits.clone(),
        )
        .unwrap();
    let session_budget = worker
        .child(session.id().into(), BudgetScope::Session, limits.clone())
        .unwrap();
    let pool = session_budget
        .child(query.id().into(), BudgetScope::Query, limits)
        .unwrap();
    let runtime = RuntimeBudget::new(pool, cancel.clone()).unwrap();
    Fixture {
        lifecycle,
        session,
        source,
        prepared,
        cancel,
        runtime,
    }
}

#[test]
fn runtime_budget_rejects_different_session_or_worker_ancestry() {
    let fixture = setup(BudgetLimits::default());
    for (worker_id, session_id) in [
        (
            fixture.cancel.worker_owner_id().unwrap(),
            "different-session".to_owned(),
        ),
        (
            "different-worker".to_owned(),
            fixture.session.id().to_owned(),
        ),
    ] {
        let limits = BudgetLimits::default();
        let global = BudgetPool::global("separate-root".into(), limits.clone()).unwrap();
        let worker = global
            .child(worker_id, BudgetScope::Worker, limits.clone())
            .unwrap();
        let session = worker
            .child(session_id, BudgetScope::Session, limits.clone())
            .unwrap();
        let pool = session
            .child(
                fixture.cancel.query_handle().id().into(),
                BudgetScope::Query,
                limits,
            )
            .unwrap();
        assert_eq!(
            RuntimeBudget::new(pool, fixture.cancel.clone())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
    }
}

#[test]
fn concurrent_execution_claims_have_exactly_one_winner() {
    let fixture = setup(BudgetLimits::default());
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let token = fixture.cancel.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            token.claim_execution()
        }));
    }
    barrier.wait();
    let outcomes: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome
                .as_ref()
                .is_err_and(|error| error.code == ErrorCode::InvalidArgument))
            .count(),
        1
    );
    assert!(fixture.cancel.status().unwrap().error.is_none());
}
fn terminal(f: &Fixture) -> TerminalBuilder {
    TerminalBuilder::new(
        ResultIdentity {
            request_id: "runtime-request".into(),
            operation: "query".into(),
            profile: "mdd-native-v1-unqualified".into(),
            sql_dialect: None,
            session_id: Some(f.session.id().into()),
            snapshot_id: Some(f.source.snapshot_id().into()),
            catalog_epoch: Some(DecimalU64(0)),
            query_id: Some(f.cancel.query_handle().id().into()),
            schema_id: Some(f.prepared.runtime_binding().unwrap().schema_id),
        },
        Coverage {
            scope_id: "generic-owned-test-table".into(),
            input: Completeness::Complete,
            facts: Completeness::Complete,
            required_layers: vec!["structure".into()],
            issues: Vec::new(),
        },
    )
    .unwrap()
}
#[test]
fn quota_after_rows_has_failure_terminal_and_preserves_real_compute_axis() {
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let f = setup(BudgetLimits::default());
        let builder = terminal(&f);
        let identity = builder.identity().clone();
        let mut receiver = StreamVerifier::new(
            identity,
            "generic-owned-test-table".into(),
            vec!["structure".into()],
        )
        .unwrap();
        let mut accepted = Vec::new();
        let mut control = Control::new(ExecutionLimits {
            max_output_rows: 2,
            ..ExecutionLimits::default()
        })
        .with_runtime(f.runtime.clone());
        let end = execute_into(
            &f.prepared,
            &f.source,
            mode,
            &mut control,
            builder,
            |sequence, row| {
                accepted.push(row.clone());
                receiver.batch(
                    sequence,
                    &f.prepared.runtime_binding().unwrap().schema_id,
                    1,
                )
            },
        )
        .unwrap();
        assert_eq!(accepted.len(), 2);
        assert_eq!(end.operation_status, OperationStatus::Error);
        assert_eq!(end.error.as_ref().unwrap().code, ErrorCode::QuotaExceeded);
        assert_eq!(end.response.emitted_rows.0, 2);
        assert!(end.response.truncated);
        assert_eq!(
            end.execution.complete,
            matches!(mode, ExecutionMode::MaterializedReference)
        );
        assert_eq!(end.coverage.facts, Completeness::Complete);
        let status = f.cancel.status().unwrap();
        assert_eq!(status.execution_complete, end.execution.complete);
        assert!(!status.delivery_complete);
        receiver.terminal(end.clone()).unwrap();
        assert_eq!(
            receiver
                .finish()
                .unwrap()
                .require_complete()
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        println!(
            "{}",
            serde_json::json!({"case":"quota-after-two-accepted-rows","mode":mode,"terminal":end,"status":status,"accepted":accepted})
        );
    }
}
#[test]
fn native_cancel_after_prefix_isolated_from_sibling_and_computed_spool_retained() {
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let f = setup(BudgetLimits::default());
        let sibling = f
            .lifecycle
            .prepare_query(
                &f.session,
                f.prepared.runtime_binding().unwrap(),
                ResourceLimits::default(),
            )
            .unwrap();
        f.lifecycle.start_query(&f.session, &sibling, 1).unwrap();
        let mut rows = 0;
        let mut control = Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone());
        let end = execute_into(
            &f.prepared,
            &f.source,
            mode,
            &mut control,
            terminal(&f),
            |_, _| {
                rows += 1;
                f.cancel.cancel()?;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(end.operation_status, OperationStatus::Cancelled);
        assert_eq!(end.response.emitted_rows.0, 1);
        assert_eq!(
            end.execution.complete,
            matches!(mode, ExecutionMode::MaterializedReference)
        );
        f.lifecycle.checkpoint(&sibling).unwrap();
        println!(
            "{}",
            serde_json::json!({"case":"native-cancel-one-query","mode":mode,"terminal":end,"sibling_active":true})
        );
    }
}
#[test]
fn zero_deadline_and_unconsumed_cursor_do_not_become_empty_success() {
    let f = setup(BudgetLimits::default().deadlines(0, 0).unwrap());
    let mut rows = 0;
    let end = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        |_, _| {
            rows += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(rows, 0);
    assert_eq!(end.error.unwrap().code, ErrorCode::DeadlineExceeded);
    let f = setup(BudgetLimits::default());
    let cursor = f
        .lifecycle
        .open_cursor(&f.session, f.cancel.query_handle())
        .unwrap();
    f.lifecycle.close_cursor(&cursor).unwrap();
    let end = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::MaterializedReference,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        |_, _| Ok(()),
    )
    .unwrap();
    assert!(end.execution.complete);
    assert_eq!(end.error.unwrap().code, ErrorCode::InvalidCursor);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}
#[test]
fn computation_claim_is_atomic_and_later_attempt_cannot_fail_original() {
    let f = setup(BudgetLimits::default());
    let first = f
        .lifecycle
        .cancellation_token(f.cancel.query_handle())
        .unwrap();
    let second = f
        .lifecycle
        .cancellation_token(f.cancel.query_handle())
        .unwrap();
    first.claim_execution().unwrap();
    assert_eq!(
        second.claim_execution().err().unwrap().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        first.status().unwrap().phase,
        mdd_session::QueryPhase::Active
    );
}

#[test]
fn runtime_owner_and_prepared_binding_are_verified_before_execution_claim() {
    let f = setup(BudgetLimits::default());
    let original = terminal(&f);
    let mut identity = original.identity().clone();
    identity.session_id = Some("another-session".into());
    let wrong = TerminalBuilder::new(identity, original.coverage().clone()).unwrap();
    let error = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        wrong,
        |_, _| Ok(()),
    )
    .err()
    .unwrap();
    assert_eq!(error.details["reason"], "TERMINAL_SESSION_OWNER");
    let different_plan = prepare(
        QueryIr {
            schema_version: IR_VERSION.into(),
            text_semantics: TEXT_VERSION.into(),
            snapshot_id: f.source.snapshot_id().into(),
            catalog_epoch: DecimalU64(0),
            require_stable_order: false,
            root: Node::Limit {
                input: Box::new(Node::Scan {
                    relation: "rows".into(),
                }),
                offset: DecimalU64(0),
                count: DecimalU64(1),
            },
        },
        &f.source,
    )
    .unwrap();
    assert_eq!(
        execute(
            &different_plan,
            &f.source,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone())
        )
        .err()
        .unwrap()
        .details["reason"],
        "RUNTIME_QUERY_SNAPSHOT_GENERATION_OR_BINDING"
    );
    let end = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        |_, _| Ok(()),
    )
    .unwrap();
    assert!(end.is_complete_result());
    assert!(f.cancel.status().unwrap().delivery_complete);
}
