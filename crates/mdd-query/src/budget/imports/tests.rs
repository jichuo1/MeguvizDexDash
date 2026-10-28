use super::*;
use mdd_facts::MetadataFacts;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

fn pool() -> BudgetPool {
    BudgetPool::global("import-owner".into(), BudgetLimits::default()).unwrap()
}
fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}
fn used(pool: &BudgetPool, resource: Resource) -> u64 {
    pool.usage().unwrap().used.get(&resource).map_or(0, |v| v.0)
}
fn raw() -> InputSpec {
    InputSpec {
        path: path("generated/minimal-035.dex"),
        kind: InputKind::RawDex,
        expected_sha256: None,
    }
}
#[test]
fn capture_reserves_before_read_and_duplicates_share_retained_owner() {
    let blocked = BudgetPool::global(
        "blocked".into(),
        BudgetLimits::default().with(Resource::InputResidentBytes, 0),
    )
    .unwrap();
    assert_eq!(
        capture(&blocked, &[raw()], CaptureLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(used(&blocked, Resource::InputBytes), 0);
    assert_eq!(used(&blocked, Resource::BuildWorkspaceBytes), 0);
    let pool = pool();
    let one = raw();
    let captured = capture(&pool, &[one.clone(), one], CaptureLimits::default()).unwrap();
    assert_eq!(captured.snapshot().sources().len(), 2);
    assert!(Arc::ptr_eq(
        &captured.snapshot().sources()[0].lease(),
        &captured.snapshot().sources()[1].lease()
    ));
    assert_eq!(
        used(&pool, Resource::InputBytes),
        captured.snapshot().manifest().captured_input_bytes.0
    );
    let bytes = captured.admitted_resident_bytes();
    assert_eq!(used(&pool, Resource::InputResidentBytes), bytes);
    assert_eq!(used(&pool, Resource::BuildWorkspaceBytes), 0);
    let alias = captured.clone();
    let separately_captured = capture(&pool, &[raw()], CaptureLimits::default()).unwrap();
    assert!(!Arc::ptr_eq(
        &alias.snapshot().sources()[0].lease(),
        &separately_captured.snapshot().sources()[0].lease()
    ));
    assert_eq!(
        used(&pool, Resource::InputResidentBytes),
        bytes + separately_captured.admitted_resident_bytes()
    );
    drop(separately_captured);
    drop(captured);
    assert_eq!(used(&pool, Resource::InputResidentBytes), bytes);
    drop(alias);
    assert_eq!(used(&pool, Resource::InputResidentBytes), 0);
}
#[test]
fn import_preserves_source_and_crc_failures_and_rejects_expand_before_materialization() {
    let pool = pool();
    let mut changed = raw();
    changed.expected_sha256 = Some("00".repeat(32));
    assert_eq!(
        capture(&pool, &[changed], CaptureLimits::default())
            .err()
            .unwrap()
            .code,
        ErrorCode::SourceChanged
    );
    assert_eq!(used(&pool, Resource::InputResidentBytes), 0);
    let blocked = BudgetPool::global(
        "expand-blocked".into(),
        BudgetLimits::default().with(Resource::UncompressedBytes, 1),
    )
    .unwrap();
    let input = InputSpec {
        path: path("zip64/generated/full-stored.zip"),
        kind: InputKind::Apk,
        expected_sha256: None,
    };
    let captured = capture(&blocked, &[input], CaptureLimits::default()).unwrap();
    assert_eq!(
        inventory(
            &blocked,
            captured,
            0,
            InventoryPolicy::default(),
            ArchiveLimits::default(),
            1024 * 1024
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(used(&blocked, Resource::ArchiveResidentBytes), 0);
    assert_eq!(used(&blocked, Resource::UncompressedBytes), 0);
    let input = InputSpec {
        path: path("generated/bad-crc.apk"),
        kind: InputKind::Apk,
        expected_sha256: None,
    };
    let captured = capture(&pool, &[input], CaptureLimits::default()).unwrap();
    let error = inventory(
        &pool,
        captured,
        0,
        InventoryPolicy::default(),
        ArchiveLimits::default(),
        1024 * 1024,
    )
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(error.details["reason"], "CRC_OR_DECOMPRESSION_FAILURE");
    assert_eq!(used(&pool, Resource::ArchiveResidentBytes), 0);
    assert_eq!(used(&pool, Resource::BuildWorkspaceBytes), 0);
}
#[test]
fn decoded_member_cache_and_published_facts_retain_source_budget_without_double_charge() {
    let pool = pool();
    let captured = capture(
        &pool,
        &[InputSpec {
            path: path("zip64/generated/full-stored.zip"),
            kind: InputKind::Apk,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .unwrap();
    let inventory = inventory(
        &pool,
        captured,
        0,
        InventoryPolicy::default(),
        ArchiveLimits::default(),
        1024 * 1024,
    )
    .unwrap();
    let id = inventory
        .inventory()
        .manifest()
        .members
        .iter()
        .find(|m| m.raw_name == b"assets/raw.bin")
        .unwrap()
        .member_id
        .clone();
    let before = used(&pool, Resource::UncompressedBytes);
    let one = inventory.member(&id).unwrap();
    let after = used(&pool, Resource::UncompressedBytes);
    assert_eq!(after, before + 10);
    let same = inventory.member(&id).unwrap();
    assert_eq!(used(&pool, Resource::UncompressedBytes), after);
    assert!(Arc::ptr_eq(&one.blob().lease(), &same.blob().lease()));
    let captured_bytes = used(&pool, Resource::InputResidentBytes);
    drop(inventory);
    assert_eq!(used(&pool, Resource::InputResidentBytes), captured_bytes);
    drop(one);
    assert_eq!(used(&pool, Resource::InputResidentBytes), captured_bytes);
    drop(same);
    assert_eq!(used(&pool, Resource::InputResidentBytes), 0);
    assert_eq!(used(&pool, Resource::ArchiveResidentBytes), 0);
    let captured = capture(&pool, &[raw()], CaptureLimits::default()).unwrap();
    let inv = super::inventory(
        &pool,
        captured,
        0,
        InventoryPolicy::default(),
        ArchiveLimits::default(),
        65536,
    )
    .unwrap();
    let facts = build_facts(
        &pool,
        inv,
        FactBounds {
            max_rows: 128,
            workspace_bytes: 65536,
            ready_bytes: 65536,
            text_bytes: 4096,
        },
        |input, limits| {
            let facts = MetadataFacts::build(
                input.source().snapshot(),
                input.inventory(),
                0,
                limits.strings,
            )?;
            let count = facts.strings().len() + facts.types().len() + facts.prototypes().len();
            Ok((facts, count as u64))
        },
    )
    .unwrap();
    assert_eq!(facts.facts().header().version, "035");
    assert_eq!(used(&pool, Resource::FactRows), 0);
    assert!(used(&pool, Resource::ReadyFactsBytes) > 0);
    drop(facts);
    assert_eq!(used(&pool, Resource::ReadyFactsBytes), 0);
    assert_eq!(used(&pool, Resource::InputResidentBytes), 0);
}
#[test]
fn facts_admission_failure_does_not_call_builder() {
    let pool = BudgetPool::global(
        "facts-admission".into(),
        BudgetLimits::default().with(Resource::ReadyFactsBytes, 0),
    )
    .unwrap();
    let captured = capture(&pool, &[raw()], CaptureLimits::default()).unwrap();
    let inv = inventory(
        &pool,
        captured,
        0,
        InventoryPolicy::default(),
        ArchiveLimits::default(),
        65536,
    )
    .unwrap();
    let called = AtomicBool::new(false);
    let error = build_facts(
        &pool,
        inv,
        FactBounds {
            max_rows: 1,
            workspace_bytes: 65536,
            ready_bytes: 1,
            text_bytes: 1024,
        },
        |_, _| {
            called.store(true, Ordering::SeqCst);
            Ok(((), 0))
        },
    )
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert!(!called.load(Ordering::SeqCst));
    assert_eq!(used(&pool, Resource::BuildWorkspaceBytes), 0);
}

#[test]
fn source_leases_require_same_tree_and_leaf_admission_before_build() {
    let owner = pool();
    let captured = capture(&owner, &[raw()], CaptureLimits::default()).unwrap();
    let other = pool();
    let before = used(&other, Resource::ArchiveMembers);
    let mismatch = inventory(
        &other,
        captured.clone(),
        0,
        InventoryPolicy::default(),
        ArchiveLimits::default(),
        65536,
    )
    .err()
    .unwrap();
    assert_eq!(mismatch.code, ErrorCode::InvalidArgument);
    assert_eq!(used(&other, Resource::ArchiveMembers), before);

    let restricted = owner
        .child(
            "restricted".into(),
            BudgetScope::Worker,
            BudgetLimits::default().with(Resource::InputResidentBytes, 0),
        )
        .unwrap();
    let failure = inventory(
        &restricted,
        captured.clone(),
        0,
        InventoryPolicy::default(),
        ArchiveLimits::default(),
        65536,
    )
    .err()
    .unwrap();
    assert_eq!(failure.code, ErrorCode::QuotaExceeded);
    assert_eq!(used(&restricted, Resource::ArchiveMembers), 0);

    let source = inventory(
        &owner,
        captured,
        0,
        InventoryPolicy::default(),
        ArchiveLimits::default(),
        65536,
    )
    .unwrap();
    let called = AtomicBool::new(false);
    let failure = build_facts(
        &restricted,
        source,
        FactBounds {
            max_rows: 64,
            workspace_bytes: 65536,
            ready_bytes: 65536,
            text_bytes: 4096,
        },
        |_, _| {
            called.store(true, Ordering::SeqCst);
            Ok(((), 0))
        },
    )
    .err()
    .unwrap();
    assert_eq!(failure.code, ErrorCode::QuotaExceeded);
    assert!(!called.load(Ordering::SeqCst));
    assert_eq!(used(&restricted, Resource::ReadyFactsBytes), 0);
}

#[test]
fn nonempty_fact_work_and_retained_memory_have_different_lifetimes() {
    let owner = pool();
    let captured = capture(
        &owner,
        &[InputSpec {
            path: path("generated/structured-035.dex"),
            kind: InputKind::RawDex,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .unwrap();
    let source = inventory(
        &owner,
        captured,
        0,
        InventoryPolicy::default(),
        ArchiveLimits::default(),
        65536,
    )
    .unwrap();
    let facts = build_facts(
        &owner,
        source,
        FactBounds {
            max_rows: 128,
            workspace_bytes: 65536,
            ready_bytes: 65536,
            text_bytes: 4096,
        },
        |input, limits| {
            let facts = MetadataFacts::build(
                input.source().snapshot(),
                input.inventory(),
                0,
                limits.strings,
            )?;
            let rows =
                (facts.strings().len() + facts.types().len() + facts.prototypes().len()) as u64;
            Ok((facts, rows))
        },
    )
    .unwrap();
    let rows = used(&owner, Resource::FactRows);
    assert!(rows > 0);
    assert!(used(&owner, Resource::ReadyFactsBytes) > 0);
    drop(facts);
    assert_eq!(used(&owner, Resource::ReadyFactsBytes), 0);
    assert_eq!(used(&owner, Resource::InputResidentBytes), 0);
    assert_eq!(used(&owner, Resource::FactRows), rows);
}
