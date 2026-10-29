use super::*;
use crate::{
    budget::{BudgetLimits, BudgetPool, BudgetScope, QueueEvent, RuntimeBudget, bounded_channel},
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
    setup_with_rows(limits, 4)
}
fn setup_with_rows(limits: BudgetLimits, rows: u64) -> Fixture {
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
                rows: (0..rows).map(|n| vec![Value::U64(DecimalU64(n))]).collect(),
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
fn queue_consumer_receives_original_required_facts_failure_end() {
    struct FailedSource<'a>(&'a MemoryCatalog);
    impl FactSource for FailedSource<'_> {
        fn identity(&self) -> &str {
            self.0.identity()
        }
        fn snapshot_id(&self) -> &str {
            self.0.snapshot_id()
        }
        fn catalog_epoch(&self) -> DecimalU64 {
            self.0.catalog_epoch()
        }
        fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
            self.0.relation_schema(relation)
        }
        fn require_layers(&self, _: &BTreeSet<FactLayer>) -> MddResult<()> {
            Err(MddError::new(
                ErrorCode::InvalidInput,
                "facts.test",
                "required producer corrupt",
            )
            .detail("reason", "CORRUPT_FACTS"))
        }
        fn validate_entity(&self, entity: &mdd_facts::EntityRef) -> MddResult<()> {
            self.0.validate_entity(entity)
        }
        fn scan<'a>(
            &'a self,
            relation: &str,
        ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
            self.0.scan(relation)
        }
        fn read_code_bytes(&self, entity: &mdd_facts::EntityRef) -> MddResult<Option<&[u8]>> {
            self.0.read_code_bytes(entity)
        }
    }
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &FailedSource(&f.source),
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("missing original error end")
    };
    let error = end.unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(error.details["reason"], "CORRUPT_FACTS");
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let terminal = receipt.finish(&mut pending).unwrap();
    assert_eq!(terminal.error.unwrap().code, ErrorCode::InvalidInput);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn cancelled_before_claim_sends_explicit_cancelled_end() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    f.cancel.cancel().unwrap();
    let error = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert!(
        sender.finish(Ok(())).is_err(),
        "cancelled query left queue without its error End"
    );
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("cancelled query had no End")
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::Cancelled);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn queued_rows_are_not_delivery_without_consumer_acknowledgement() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(f.cancel.status().unwrap().execution_complete);
    assert!(!f.cancel.status().unwrap().delivery_complete);
    for n in 0..4 {
        let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
            panic!("missing row")
        };
        assert_eq!(packet.payload(), &vec![Value::U64(DecimalU64(n))]);
        packet.acknowledge().unwrap();
    }
    assert!(!f.cancel.status().unwrap().delivery_complete);
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let end = receipt.finish(&mut pending).unwrap();
    assert!(end.is_complete_result());
    assert_eq!(end.response.emitted_rows.0, 4);
    assert!(f.cancel.status().unwrap().delivery_complete);
    assert!(receipt.finish(&mut pending).is_err());
}

#[test]
fn trusted_callback_cannot_complete_a_query_bound_unread_queue() {
    let f = setup(BudgetLimits::default());
    let (sender, _receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let terminal = execute_trusted_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        |_, row| sender.send(row.clone(), 16),
    )
    .unwrap();
    assert!(!terminal.is_complete_result());
    assert_eq!(terminal.error.unwrap().code, ErrorCode::InvalidCursor);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn all_rows_dequeued_but_one_unacknowledged_still_cannot_complete() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let _pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    for _ in 0..3 {
        let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
            panic!("missing row")
        };
        packet.acknowledge().unwrap();
    }
    let QueueEvent::Data(unacknowledged) = receiver.receive().unwrap() else {
        panic!("missing final row")
    };
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    assert!(receiver.into_delivery_receipt().is_err());
    assert!(!f.cancel.status().unwrap().delivery_complete);
    drop(unacknowledged);
}

#[test]
fn empty_queue_needs_explicit_end_and_unbound_queue_cannot_prove_delivery() {
    let f = setup_with_rows(BudgetLimits::default(), 0);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(!f.cancel.status().unwrap().delivery_complete);
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    assert!(receipt.finish(&mut pending).unwrap().is_complete_result());
    let f = setup(BudgetLimits::default());
    let (sender, _receiver) = bounded_channel(f.runtime.pool().clone(), None, 8).unwrap();
    assert!(
        execute_into(
            &f.prepared,
            &f.source,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
            terminal(&f),
            &sender
        )
        .is_err()
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn dropped_unacknowledged_rows_and_unread_end_never_complete() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let _pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("missing row")
    };
    drop(packet);
    assert!(!f.cancel.status().unwrap().delivery_complete);
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::Cancelled
    );
    let f = setup_with_rows(BudgetLimits::default(), 0);
    let (sender, receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let _pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(receiver.into_delivery_receipt().is_err());
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn queue_quota_delivers_only_acknowledged_prefix_with_failure_end() {
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let f = setup(BudgetLimits::default());
        let (sender, mut receiver) =
            bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
        let mut pending = execute_into(
            &f.prepared,
            &f.source,
            mode,
            &mut Control::new(ExecutionLimits {
                max_output_rows: 2,
                ..ExecutionLimits::default()
            })
            .with_runtime(f.runtime.clone()),
            terminal(&f),
            &sender,
        )
        .unwrap();
        for _ in 0..2 {
            let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
                panic!("missing prefix")
            };
            packet.acknowledge().unwrap();
        }
        let QueueEvent::End(end) = receiver.receive().unwrap() else {
            panic!("missing error end")
        };
        assert_eq!(end.unwrap_err().code, ErrorCode::QuotaExceeded);
        let mut receipt = receiver.into_delivery_receipt().unwrap();
        let terminal = receipt.finish(&mut pending).unwrap();
        assert_eq!(terminal.error.unwrap().code, ErrorCode::QuotaExceeded);
        assert_eq!(terminal.response.emitted_rows.0, 2);
        assert!(terminal.response.truncated);
        assert!(!f.cancel.status().unwrap().delivery_complete);
    }
}

#[test]
fn queue_deadline_has_explicit_error_end_and_no_complete_success() {
    let f = setup(BudgetLimits::default().deadlines(0, 0).unwrap());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("deadline became data or EOF")
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::DeadlineExceeded);
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let terminal = receipt.finish(&mut pending).unwrap();
    assert_eq!(terminal.error.unwrap().code, ErrorCode::DeadlineExceeded);
    assert!(!terminal.execution.complete);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn receipt_cannot_confirm_another_query() {
    fn ready(f: &Fixture) -> (PendingDelivery, crate::budget::QueueDeliveryReceipt) {
        let (sender, mut receiver) =
            bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
        let pending = execute_into(
            &f.prepared,
            &f.source,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
            terminal(f),
            &sender,
        )
        .unwrap();
        for _ in 0..4 {
            let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
                panic!("missing row")
            };
            packet.acknowledge().unwrap();
        }
        assert!(matches!(
            receiver.receive().unwrap(),
            QueueEvent::End(Ok(()))
        ));
        (pending, receiver.into_delivery_receipt().unwrap())
    }
    let a = setup(BudgetLimits::default());
    let b = setup(BudgetLimits::default());
    let (mut pending_a, mut receipt_a) = ready(&a);
    let (mut pending_b, mut receipt_b) = ready(&b);
    assert!(receipt_a.finish(&mut pending_b).is_err());
    assert!(
        !a.cancel.status().unwrap().delivery_complete
            && !b.cancel.status().unwrap().delivery_complete
    );
    assert!(
        receipt_a
            .finish(&mut pending_a)
            .unwrap()
            .is_complete_result()
    );
    assert!(
        receipt_b
            .finish(&mut pending_b)
            .unwrap()
            .is_complete_result()
    );
}

#[test]
fn error_receipt_requires_every_original_error_field() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel::<Row>(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let original = MddError::new(ErrorCode::InvalidInput, "facts.input", "corrupt")
        .detail("reason", "BAD_ITEM");
    sender.finish(Err(original.clone())).unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Err(_))
    ));
    let receipt = receiver.into_delivery_receipt().unwrap();
    assert!(
        receipt
            .matches(&sender, &f.runtime, 0, Some(&original))
            .unwrap()
    );
    let mut differences = Vec::new();
    let mut changed = original.clone();
    changed.code = ErrorCode::UnsupportedQuery;
    differences.push(changed);
    let mut changed = original.clone();
    changed.stage = "other".into();
    differences.push(changed);
    let mut changed = original.clone();
    changed.message = "other".into();
    differences.push(changed);
    let mut changed = original.clone();
    changed.retryable = true;
    differences.push(changed);
    let mut changed = original.clone();
    changed.details.insert("reason".into(), "OTHER".into());
    differences.push(changed);
    for changed in differences {
        assert!(
            !receipt
                .matches(&sender, &f.runtime, 0, Some(&changed))
                .unwrap()
        );
    }
    assert!(!receipt.matches(&sender, &f.runtime, 0, None).unwrap());
}

#[test]
fn wrong_terminal_binding_does_not_poison_or_claim_the_original_queue() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let original = terminal(&f);
    let mut identity = original.identity().clone();
    identity.session_id = Some("different-session".into());
    let wrong = TerminalBuilder::new(identity, original.coverage().clone()).unwrap();
    let error = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        wrong,
        &sender,
    )
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(f.cancel.status().unwrap().error.is_none());
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    for _ in 0..4 {
        let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
            panic!("missing row")
        };
        packet.acknowledge().unwrap();
    }
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    assert!(receipt.finish(&mut pending).unwrap().is_complete_result());
}

#[test]
fn queue_with_real_backpressure_completes_only_after_consumer_end() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 1).unwrap();
    std::thread::scope(|scope| {
        let fixture = &f;
        let producer = scope.spawn(move || {
            execute_into(
                &fixture.prepared,
                &fixture.source,
                ExecutionMode::Streaming,
                &mut Control::new(ExecutionLimits::default()).with_runtime(fixture.runtime.clone()),
                terminal(fixture),
                &sender,
            )
            .unwrap()
        });
        for n in 0..4 {
            let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
                panic!("missing backpressured row")
            };
            assert_eq!(packet.payload(), &vec![Value::U64(DecimalU64(n))]);
            assert!(!f.cancel.status().unwrap().delivery_complete);
            packet.acknowledge().unwrap();
        }
        assert!(matches!(
            receiver.receive().unwrap(),
            QueueEvent::End(Ok(()))
        ));
        let mut pending = producer.join().unwrap();
        assert!(!f.cancel.status().unwrap().delivery_complete);
        let mut receipt = receiver.into_delivery_receipt().unwrap();
        assert!(receipt.finish(&mut pending).unwrap().is_complete_result());
    });
    assert!(f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn duplicate_end_and_out_of_order_ack_are_sticky_failures() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let duplicate = sender.try_clone().unwrap();
    let _pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(duplicate.finish(Ok(())).is_err());
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::InvalidArgument
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);
    let QueueEvent::Data(first) = receiver.receive().unwrap() else {
        panic!("missing queued row")
    };
    assert!(first.acknowledge().is_err());
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let _pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::Data(first) = receiver.receive().unwrap() else {
        panic!("missing first")
    };
    let QueueEvent::Data(second) = receiver.receive().unwrap() else {
        panic!("missing second")
    };
    assert_eq!(
        second.acknowledge().unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    drop(first);
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::InvalidArgument
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn worker_loss_and_cancel_before_final_receipt_are_not_success() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    sender.send(vec![Value::U64(DecimalU64(1))], 16).unwrap();
    drop(sender);
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::WorkerLost
    );
    let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("missing prefix")
    };
    packet.acknowledge().unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("missing lost end")
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::WorkerLost);
    drop(receiver);
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::WorkerLost
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);

    let f = setup_with_rows(BudgetLimits::default(), 0);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    f.cancel.cancel().unwrap();
    assert!(receipt.finish(&mut pending).is_err());
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::Cancelled
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);
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
        let end = execute_trusted_into(
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
        let end = execute_trusted_into(
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
    let end = execute_trusted_into(
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
    let end = execute_trusted_into(
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
    let error = execute_trusted_into(
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
    let end = execute_trusted_into(
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
