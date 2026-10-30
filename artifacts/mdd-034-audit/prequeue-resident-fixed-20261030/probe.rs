//! Independent bounded probe of queue-owned row capacity; synthetic data only.
use mdd_facts::{EntityKind, EntityRef};
use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
use mdd_query::{
    budget::{bounded_channel, BudgetLimits, BudgetPool, BudgetScope, QueueEvent, Resource, RuntimeBudget},
    executor::{execute_into, prepare, Control, ExecutionLimits, ExecutionMode, FactSource, PreparedQuery, RelationSchema},
    ir::{Bytes, Column, DataType, FactLayer, Node, QueryIr, Row, Value, IR_VERSION, TEXT_VERSION},
};
use mdd_session::{cancellation::QueryCancellation, Lifecycle, ResourceLimits, SessionHandle};
use mdd_types::{result::{ResultIdentity, TerminalBuilder}, Completeness, Coverage, DecimalU64, ErrorCode, MddError, MddResult};
use serde_json::{json, Value as Json};
use std::{collections::{BTreeMap, BTreeSet}, path::PathBuf, sync::{Arc, Mutex}};

fn ensure(value: bool, message: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.to_owned()) }
}
fn unwrap<T, E: std::fmt::Debug>(value: Result<T, E>) -> Result<T, String> {
    value.map_err(|e| format!("{e:?}"))
}
fn used(pool: &BudgetPool, resource: Resource) -> Result<u64, String> {
    Ok(unwrap(pool.usage())?.used.get(&resource).map_or(0, |n| n.0))
}

struct Source { snapshot: String, rows: usize, large: bool }
impl Source {
    fn row(&self) -> Row {
        let (row_cap, text_cap, bytes_cap, id_cap, occurrence_cap) = if self.large {
            (37, 313, 571, 211, 137)
        } else {
            (4, 1, 1, self.snapshot.len(), 5)
        };
        let mut text = Vec::with_capacity(text_cap);
        text.extend([65, 0, 0xd800]);
        let mut bytes = Vec::with_capacity(bytes_cap);
        bytes.extend([0, 0xff, 0x41]);
        let entity = || {
            let mut snapshot_id = String::with_capacity(id_cap);
            snapshot_id.push_str(&self.snapshot);
            let mut dex_occurrence_id = String::with_capacity(occurrence_cap);
            dex_occurrence_id.push_str("dex-a");
            Value::Entity(EntityRef { snapshot_id, dex_occurrence_id, kind: EntityKind::String, local_index: 7 })
        };
        let mut row = Vec::with_capacity(row_cap);
        row.extend([Value::Utf16(text), Value::Bytes(Bytes(bytes)), entity(), entity()]);
        row
    }
}
impl FactSource for Source {
    fn identity(&self) -> &str { "independent-sparse-mixed-source" }
    fn snapshot_id(&self) -> &str { &self.snapshot }
    fn catalog_epoch(&self) -> DecimalU64 { DecimalU64(0) }
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
        if relation != "rows" { return Err(MddError::new(ErrorCode::InvalidArgument, "probe", "unknown relation")); }
        let columns = [DataType::Utf16, DataType::Bytes, DataType::Entity, DataType::Entity].into_iter()
            .enumerate().map(|(i, data_type)| Column { id: format!("c{i}"), display_name: format!("c{i}"), data_type, nullable: false }).collect();
        Ok(RelationSchema { columns, required_layers: vec![FactLayer::Structure] })
    }
    fn require_layers(&self, _: &BTreeSet<FactLayer>) -> MddResult<()> { Ok(()) }
    fn validate_entity(&self, entity: &EntityRef) -> MddResult<()> {
        if entity.snapshot_id == self.snapshot && entity.dex_occurrence_id == "dex-a" { Ok(()) }
        else { Err(MddError::new(ErrorCode::InvalidArgument, "probe", "foreign entity")) }
    }
    fn scan<'a>(&'a self, _: &str) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
        Ok(Box::new((0..self.rows).map(|_| Ok(self.row()))))
    }
    fn read_code_bytes(&self, _: &EntityRef) -> MddResult<Option<&[u8]>> {
        Err(MddError::new(ErrorCode::InvalidArgument, "probe", "no code"))
    }
}
struct Fixture { _lifecycle: Lifecycle, session: SessionHandle, source: Source, prepared: PreparedQuery,
                 cancel: QueryCancellation, runtime: RuntimeBudget, global: BudgetPool, worker: BudgetPool, session_budget: BudgetPool }
fn fixture(limits: BudgetLimits, rows: usize, large: bool) -> Result<Fixture, String> {
    let path = PathBuf::from("tests/fixtures/generated/minimal-035.dex");
    let snapshot = Arc::new(unwrap(Snapshot::capture(&[InputSpec { path, kind: InputKind::RawDex, expected_sha256: None }], CaptureLimits::default()))?);
    let source = Source { snapshot: snapshot.manifest().snapshot_id.clone(), rows, large };
    let lifecycle = unwrap(Lifecycle::new(ResourceLimits::default()))?;
    let handle = unwrap(lifecycle.register_snapshot(snapshot))?;
    let session = unwrap(lifecycle.open_session(&handle, ResourceLimits::default()))?;
    let prepared = unwrap(prepare(QueryIr { schema_version: IR_VERSION.into(), text_semantics: TEXT_VERSION.into(),
        snapshot_id: source.snapshot.clone(), catalog_epoch: DecimalU64(0), require_stable_order: false,
        root: Node::Scan { relation: "rows".into() } }, &source))?;
    let query = unwrap(lifecycle.prepare_query(&session, unwrap(prepared.runtime_binding())?, ResourceLimits::default()))?;
    unwrap(lifecycle.start_query(&session, &query, 1))?;
    let cancel = unwrap(lifecycle.cancellation_token(&query))?;
    let global = unwrap(BudgetPool::global("independent-root".into(), limits.clone()))?;
    let worker = unwrap(global.child(unwrap(cancel.worker_owner_id())?, BudgetScope::Worker, limits.clone()))?;
    let session_budget = unwrap(worker.child(session.id().into(), BudgetScope::Session, limits.clone()))?;
    let pool = unwrap(session_budget.child(query.id().into(), BudgetScope::Query, limits))?;
    let runtime = unwrap(RuntimeBudget::new(pool, cancel.clone()))?;
    Ok(Fixture { _lifecycle: lifecycle, session, source, prepared, cancel, runtime, global, worker, session_budget })
}
fn terminal(f: &Fixture) -> Result<TerminalBuilder, String> {
    unwrap(TerminalBuilder::new(ResultIdentity {
        request_id: "independent-row-capacity".into(), operation: "query".into(), profile: "unqualified".into(), sql_dialect: None,
        session_id: Some(f.session.id().into()), snapshot_id: Some(f.source.snapshot.clone()), catalog_epoch: Some(DecimalU64(0)),
        query_id: Some(f.cancel.query_handle().id().into()), schema_id: Some(unwrap(f.prepared.runtime_binding())?.schema_id),
    }, Coverage { scope_id: "independent-four-columns".into(), input: Completeness::Complete, facts: Completeness::Complete,
                  required_layers: vec!["structure".into()], issues: vec![] }))
}
fn resident(row: &Row) -> Result<u64, String> {
    let mut total = std::mem::size_of::<Row>() + row.capacity() * std::mem::size_of::<Value>();
    for value in row {
        total += match value {
            Value::Utf16(v) => v.capacity() * std::mem::size_of::<u16>(),
            Value::Bytes(v) => v.0.capacity(),
            Value::Entity(v) => v.snapshot_id.capacity() + v.dex_occurrence_id.capacity(),
            _ => 0,
        };
    }
    u64::try_from(total).map_err(|_| "probe size conversion".to_owned())
}
fn pools(f: &Fixture) -> [&BudgetPool; 4] { [&f.global, &f.worker, &f.session_budget, f.runtime.pool()] }
fn all_usage(f: &Fixture, resource: Resource, expected: u64) -> Result<(), String> {
    for pool in pools(f) { ensure(used(pool, resource)? == expected, &format!("{resource:?}: wrong ancestor charge"))?; }
    Ok(())
}
fn complete_two_rows(large: bool) -> Result<Json, String> {
    let f = fixture(BudgetLimits::default(), 2, large)?;
    let expected_wire = unwrap(serde_json::to_vec(&f.source.row()))?.len() as u64;
    let (sender, mut receiver) = unwrap(bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2))?;
    let mut pending = unwrap(execute_into(&f.prepared, &f.source, ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()), terminal(&f)?, &sender))?;
    all_usage(&f, Resource::QueueBytes, expected_wire*2)?;
    all_usage(&f, Resource::QueueItems, 2)?;
    let QueueEvent::Data(first) = unwrap(receiver.receive())? else { return Err("first data missing".into()) };
    let QueueEvent::Data(second) = unwrap(receiver.receive())? else { return Err("second data missing".into()) };
    let a = first.payload(); let b = second.payload();
    ensure(a == b, "identical contents differ")?;
    ensure(a.as_ptr() != b.as_ptr(), "row allocations unexpectedly shared")?;
    let (Value::Utf16(ta), Value::Utf16(tb), Value::Bytes(ba), Value::Bytes(bb), Value::Entity(e1), Value::Entity(e2)) = (&a[0],&b[0],&a[1],&b[1],&a[2],&a[3]) else { return Err("unexpected schema".into()) };
    ensure(ta.as_ptr()!=tb.as_ptr() && ba.0.as_ptr()!=bb.0.as_ptr(), "independent buffers unexpectedly shared")?;
    ensure(e1==e2 && e1.snapshot_id.as_ptr()!=e2.snapshot_id.as_ptr() && e1.dex_occurrence_id.as_ptr()!=e2.dex_occurrence_id.as_ptr(), "same entity values must own separate strings")?;
    let one = resident(a)?; let two = resident(b)?;
    let wire = unwrap(serde_json::to_vec(a))?.len() as u64;
    ensure(wire == expected_wire, "wire length changed between equivalent rows")?;
    all_usage(&f, Resource::QueryWorkspaceBytes, one+two)?;
    all_usage(&f, Resource::ResidentBytes, one+two)?;
    all_usage(&f, Resource::QueueBytes, 0)?;
    all_usage(&f, Resource::OutputBytes, wire*2)?;
    ensure(!unwrap(f.cancel.status())?.delivery_complete, "delivery complete before acknowledgements")?;
    unwrap(first.acknowledge())?;
    all_usage(&f, Resource::QueryWorkspaceBytes, two)?;
    unwrap(second.acknowledge())?;
    all_usage(&f, Resource::QueryWorkspaceBytes, 0)?;
    ensure(!unwrap(f.cancel.status())?.delivery_complete, "delivery complete before End")?;
    ensure(matches!(unwrap(receiver.receive())?, QueueEvent::End(Ok(()))), "End missing")?;
    let mut receipt = unwrap(receiver.into_delivery_receipt())?;
    let envelope = unwrap(receipt.finish(&mut pending))?;
    ensure(envelope.is_complete_result() && unwrap(f.cancel.status())?.delivery_complete, "delivery did not complete")?;
    Ok(json!({"case": if large {"mixed_sparse_two_rows"} else {"mixed_compact_two_rows"},
        "per_row_resident": [one,two], "wire_bytes":wire,"identical_entity_values_separate_buffers":true,
        "separate_row_and_inner_allocations":true,"queued_bytes_before_receive":wire*2,
        "queued_items_before_receive":2,"queued_bytes_after_receive":0,"output_bytes":wire*2,
        "ack_release_each":true,"complete_only_after_end_and_receipt":true}))
}
fn quota_case(resource: Resource, limit: u64, expected_wire: u64) -> Result<Json, String> {
    let limits = BudgetLimits::default().with(resource, limit);
    let f = fixture(limits, 1, true)?;
    let observed_row = f.source.row();
    let observed_resident = resident(&observed_row)?;
    let observed_wire = unwrap(serde_json::to_vec(&observed_row))?.len() as u64;
    ensure(observed_wire == expected_wire, "quota sample wire identity differs")?;
    ensure(match resource { Resource::QueryWorkspaceBytes => observed_resident > limit,
                            Resource::QueueBytes | Resource::OutputBytes => observed_wire > limit,
                            _ => false }, "quota test limit does not constrain selected resource")?;
    drop(observed_row);
    let (sender, mut receiver) = unwrap(bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2))?;
    let phases = Arc::new(Mutex::new(BTreeMap::<String, u64>::new()));
    let captured = Arc::clone(&phases);
    let mut control = Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()).with_hook(move |checkpoint| {
        let mut counts = captured.lock().map_err(|_| MddError::new(ErrorCode::InternalFault, "probe", "phase lock poisoned"))?;
        let count = counts.entry(checkpoint.phase.to_owned()).or_default();
        *count = count.checked_add(1).ok_or_else(|| MddError::new(ErrorCode::InternalFault, "probe", "phase count overflow"))?;
        Ok(())
    });
    let mut pending = unwrap(execute_into(&f.prepared, &f.source, ExecutionMode::Streaming,
        &mut control, terminal(&f)?, &sender))?;
    let QueueEvent::End(end) = unwrap(receiver.receive())? else { return Err(format!("{resource:?} quota produced data; limit={limit}")) };
    let error = match end { Err(error) if error.code==ErrorCode::QuotaExceeded => error,
                            _ => return Err(format!("{resource:?} quota terminal missing")) };
    let mut receipt = unwrap(receiver.into_delivery_receipt())?;
    let envelope = unwrap(receipt.finish(&mut pending))?;
    ensure(envelope.error.as_ref().is_some_and(|e| e.code==ErrorCode::QuotaExceeded), "quota envelope missing")?;
    ensure(!unwrap(f.cancel.status())?.delivery_complete, "failed delivery claimed complete")?;
    all_usage(&f, Resource::QueryWorkspaceBytes, 0)?;
    all_usage(&f, Resource::QueueBytes, 0)?;
    let output = used(f.runtime.pool(), Resource::OutputBytes)?;
    let phase_counts = phases.lock().map_err(|_| "phase lock poisoned".to_owned())?.clone();
    let json_steps = phase_counts.get("json_count").copied().unwrap_or(0);
    let output_steps = phase_counts.get("output_row").copied().unwrap_or(0);
    let observation = json!({"event":"quota_observed","resource":format!("{resource:?}"),"limit":limit,
        "row_resident_capacity_bytes":observed_resident,"full_wire_bytes_independent":observed_wire,
        "terminal_error":&error,"json_count_steps":json_steps,"output_row_steps":output_steps,
        "query_steps":used(f.runtime.pool(), Resource::QuerySteps)?,"query_work_bytes":used(f.runtime.pool(), Resource::QueryWorkBytes)?,
        "output_bytes_charged":output,"workspace_after":0,"queue_bytes_after":0,
        "delivery_complete":false,"envelope_complete":envelope.is_complete_result()});
    eprintln!("{observation}");
    match resource {
        Resource::QueryWorkspaceBytes => {
            ensure(output==0 && json_steps==0 && output_steps==0,
                   "workspace quota did not fail before JSON count/output charge")?;
        }
        Resource::OutputBytes => {
            ensure(output==0 && json_steps>0 && output_steps==0,
                   "output quota did not stop during JSON count before output charge")?;
            ensure(error.details.get("encoded_length_exact")==Some(&json!(false)),
                   "partial encoded count falsely marked exact")?;
        }
        Resource::QueueBytes => {
            ensure(output==expected_wire && json_steps>0 && output_steps>0,
                   "queue quota did not occur after full count/output charge")?;
        }
        _ => return Err("unexpected quota resource".into()),
    }
    Ok(observation)
}
fn cancelled_held_packet() -> Result<Json, String> {
    let f = fixture(BudgetLimits::default(), 1, true)?;
    let (sender, mut receiver) = unwrap(bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2))?;
    let _pending = unwrap(execute_into(&f.prepared, &f.source, ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()), terminal(&f)?, &sender))?;
    let QueueEvent::Data(packet) = unwrap(receiver.receive())? else { return Err("held packet missing".into()) };
    let held = resident(packet.payload())?;
    all_usage(&f, Resource::QueryWorkspaceBytes, held)?;
    let clone = packet.payload().clone();
    ensure(clone.as_ptr()!=packet.payload().as_ptr(), "downstream clone shares row allocation")?;
    unwrap(f.cancel.cancel())?;
    all_usage(&f, Resource::QueryWorkspaceBytes, held)?;
    unwrap(packet.acknowledge())?;
    all_usage(&f, Resource::QueryWorkspaceBytes, 0)?;
    ensure(!unwrap(f.cancel.status())?.delivery_complete && clone.len()==4, "cancelled delivery or clone state wrong")?;
    Ok(json!({"case":"cancel_held_then_ack","held_during_cancel":held,"workspace_after_ack":0,
        "delivery_complete":false,"unaccounted_downstream_clone_still_alive":true}))
}
fn missing_end() -> Result<Json, String> {
    let f = fixture(BudgetLimits::default(), 1, false)?;
    let (sender, mut receiver) = unwrap(bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2))?;
    let _pending = unwrap(execute_into(&f.prepared, &f.source, ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()), terminal(&f)?, &sender))?;
    let QueueEvent::Data(packet) = unwrap(receiver.receive())? else { return Err("packet missing".into()) };
    unwrap(packet.acknowledge())?;
    ensure(receiver.into_delivery_receipt().is_err(), "receipt accepted before End")?;
    ensure(!unwrap(f.cancel.status())?.delivery_complete, "missing End marked complete")?;
    Ok(json!({"case":"ack_without_end","receipt_rejected":true,"delivery_complete":false}))
}
fn overflow() -> Result<Json, String> {
    let limits = BudgetLimits::default().with(Resource::QueryWorkspaceBytes, u64::MAX).with(Resource::ResidentBytes, u64::MAX);
    let pool = unwrap(BudgetPool::global("overflow-probe".into(), limits))?;
    let lease = unwrap(pool.reserve(Resource::QueryWorkspaceBytes, u64::MAX))?;
    let error = match pool.reserve(Resource::QueryWorkspaceBytes, 1) { Ok(_) => return Err("overflow accepted".into()), Err(e) => e };
    ensure(error.code==ErrorCode::QuotaExceeded && used(&pool,Resource::QueryWorkspaceBytes)?==u64::MAX, "overflow not atomic quota")?;
    drop(lease);
    ensure(used(&pool,Resource::QueryWorkspaceBytes)?==0 && used(&pool,Resource::ResidentBytes)?==0, "overflow lease not released")?;
    Ok(json!({"case":"budget_counter_overflow","error":"QUOTA_EXCEEDED","original_retained_until_drop":true,"after_drop":0,
        "row_capacity_overflow":"not safely materializable; checked arithmetic reviewed statically"}))
}
fn observed(case: Json) -> Json {
    eprintln!("{}", json!({"event":"case_completed", "observation":&case}));
    case
}
fn fixed_observation() -> Result<Json, String> {
    let initial=fixture(BudgetLimits::default(),1,true)?;
    let row=initial.source.row();let one=resident(&row)?;let wire=unwrap(serde_json::to_vec(&row))?.len() as u64;
    let limit=one+one/2;drop(row);drop(initial);
    let f=fixture(BudgetLimits::default().with(Resource::QueryWorkspaceBytes,limit),2,true)?;
    let (sender,mut receiver)=unwrap(bounded_channel(f.runtime.pool().clone(),Some(f.cancel.clone()),2))?;
    let samples=Arc::new(Mutex::new(Vec::<Json>::new()));let observations=Arc::clone(&samples);
    let second_steps=Arc::new(std::sync::atomic::AtomicU64::new(0));let observed_steps=Arc::clone(&second_steps);
    let pool=f.runtime.pool().clone();let mut rows_completed=0u64;let mut sampled_first=false;let mut second_count_steps=0u64;
    let mut control=Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()).with_hook(move|checkpoint|{
        if checkpoint.phase=="output_row" {rows_completed+=1;}
        if checkpoint.phase=="json_count" && rows_completed==0 && !sampled_first {
            sampled_first=true;let usage=pool.usage()?;let charge=|r|usage.used.get(&r).map_or(0,|n|n.0);
            observations.lock().map_err(|_|MddError::new(ErrorCode::InternalFault,"probe","lock"))?.push(json!({
              "phase":"first_row_json_count","queue_items":charge(Resource::QueueItems),"workspace_accounted":charge(Resource::QueryWorkspaceBytes),
              "resident_accounted":charge(Resource::ResidentBytes),"output_charged":charge(Resource::OutputBytes)}));
        }
        if checkpoint.phase=="json_count" && rows_completed>0 {second_count_steps+=1;observed_steps.fetch_add(1,std::sync::atomic::Ordering::SeqCst);}
        if checkpoint.phase=="output_row" {observations.lock().map_err(|_|MddError::new(ErrorCode::InternalFault,"probe","lock"))?.push(json!({"phase":"output_row","rows_completed":rows_completed,"second_json_count_steps":second_count_steps}));}
        Ok(())
    });
    let mut pending=unwrap(execute_into(&f.prepared,&f.source,ExecutionMode::Streaming,&mut control,terminal(&f)?,&sender))?;
    let sample=samples.lock().map_err(|_|"sample lock".to_owned())?.clone();
    ensure(sample.len()==2 && sample[0]["phase"]==json!("first_row_json_count") && sample[1]["rows_completed"]==json!(1),"unexpected count or output stages")?;
    ensure(sample[0]["workspace_accounted"]==json!(one) && sample[0]["resident_accounted"]==json!(one) && sample[0]["queue_items"]==json!(0),"first row was not reserved during count")?;
    ensure(second_steps.load(std::sync::atomic::Ordering::SeqCst)==0,"second row counted before reservation")?;
    let before=used(f.runtime.pool(),Resource::QueryWorkspaceBytes)?;let items=used(f.runtime.pool(),Resource::QueueItems)?;let output=used(f.runtime.pool(),Resource::OutputBytes)?;
    ensure(before==one && items==1 && output==wire,"unexpected producer accounting")?;
    let first=match unwrap(receiver.receive())? {QueueEvent::Data(packet)=>packet,_=>return Err("first row unavailable".into())};
    ensure(resident(first.payload())?==one,"first row capacity differs")?;
    unwrap(first.acknowledge())?;ensure(used(f.runtime.pool(),Resource::QueryWorkspaceBytes)?==0,"ack did not release first reservation")?;
    let end=match unwrap(receiver.receive())? {QueueEvent::End(Err(error))=>error,_=>return Err("expected quota terminal absent".into())};
    ensure(end.code==ErrorCode::QuotaExceeded && end.details.get("budget")==Some(&json!("query_workspace_bytes")),"terminal is not workspace quota")?;
    let mut receipt=unwrap(receiver.into_delivery_receipt())?;let envelope=unwrap(receipt.finish(&mut pending))?;
    ensure(!envelope.is_complete_result(),"partial query falsely complete")?;
    Ok(json!({"status":"passed_fixed_scoped","per_row_logical_capacity":one,"workspace_limit":limit,"would_be_capacity":one*2,
       "phase_samples":sample,"second_row_json_count_steps":0,"first_row_consumed_and_acknowledged":true,
       "workspace_before_receive":before,"queue_items_before_receive":items,"output_bytes_after_producer":output,"wire_per_row":wire,
       "workspace_after_ack":0,"terminal":end,"complete_result":envelope.is_complete_result(),
       "scope":"synthetic Source and real query-bound in-process queue; logical row capacities, not RSS or production qualification"}))
}
fn main(){match fixed_observation(){Ok(v)=>println!("{v}"),Err(e)=>{eprintln!("{e}");std::process::exit(1);}}}
