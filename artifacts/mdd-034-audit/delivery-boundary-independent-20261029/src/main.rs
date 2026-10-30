use mdd_input::snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot};
use mdd_query::{budget::{bounded_channel,BudgetLimits,BudgetPool,BudgetScope,Resource,RuntimeBudget,QueueEvent},executor::{prepare,execute_into,Control,ExecutionLimits,ExecutionMode,FactSource,facts::{MemoryCatalog,Table}},ir::{Column,DataType,FactLayer,Node,QueryIr,Value,IR_VERSION,TEXT_VERSION}};
use mdd_session::{Lifecycle,ResourceLimits};
use mdd_types::{Completeness,Coverage,DecimalU64,result::{ResultIdentity,TerminalBuilder}};
use std::{collections::{BTreeMap,BTreeSet},path::PathBuf,sync::Arc};

fn main(){
 let snapshot=Arc::new(Snapshot::capture(&[InputSpec{path:PathBuf::from("tests/fixtures/generated/minimal-035.dex"),kind:InputKind::RawDex,expected_sha256:None}],CaptureLimits::default()).unwrap());
 let snapshot_id=snapshot.manifest().snapshot_id.clone();
 let life=Lifecycle::new(ResourceLimits::default()).unwrap();let handle=life.register_snapshot(snapshot).unwrap();
 let session=life.open_session(&handle,ResourceLimits::default()).unwrap();
 let source=MemoryCatalog::new(snapshot_id.clone(),DecimalU64(0),BTreeMap::from([("rows".into(),Table{
  columns:vec![Column{id:"n".into(),display_name:"n".into(),data_type:DataType::U64,nullable:false}],
  required_layers:vec![FactLayer::Structure],rows:(0..4).map(|n|vec![Value::U64(DecimalU64(n))]).collect()})]),
  BTreeSet::from([FactLayer::Structure])).unwrap();
 let prepared=prepare(QueryIr{schema_version:IR_VERSION.into(),text_semantics:TEXT_VERSION.into(),snapshot_id:snapshot_id.clone(),catalog_epoch:DecimalU64(0),require_stable_order:false,root:Node::Scan{relation:"rows".into()}},&source).unwrap();
 let query=life.prepare_query(&session,prepared.runtime_binding().unwrap(),ResourceLimits::default()).unwrap();
 life.start_query(&session,&query,1).unwrap();let cancel=life.cancellation_token(&query).unwrap();
 let limits=BudgetLimits::default();let global=BudgetPool::global("delivery-root".into(),limits.clone()).unwrap();
 let worker=global.child(cancel.worker_owner_id().unwrap(),BudgetScope::Worker,limits.clone()).unwrap();
 let session_pool=worker.child(session.id().into(),BudgetScope::Session,limits.clone()).unwrap();
 let pool=session_pool.child(query.id().into(),BudgetScope::Query,limits).unwrap();
 let runtime=RuntimeBudget::new(pool.clone(),cancel.clone()).unwrap();
 let builder=TerminalBuilder::new(ResultIdentity{request_id:"test".into(),operation:"query".into(),profile:"native-unqualified".into(),sql_dialect:None,session_id:Some(session.id().into()),snapshot_id:Some(source.snapshot_id().into()),catalog_epoch:Some(DecimalU64(0)),query_id:Some(query.id().into()),schema_id:Some(prepared.runtime_binding().unwrap().schema_id)},Coverage{scope_id:"synthetic".into(),input:Completeness::Complete,facts:Completeness::Complete,required_layers:vec!["structure".into()],issues:vec![]}).unwrap();
 let (sender,mut receiver)=bounded_channel(pool.clone(),Some(cancel.clone()),8).unwrap();
 let mut control=Control::new(ExecutionLimits::default()).with_runtime(runtime);
 let end=execute_into(&prepared,&source,ExecutionMode::Streaming,&mut control,builder,|_,row|sender.send(row.clone(),16)).unwrap();
 let before=cancel.status().unwrap();let queued=pool.usage().unwrap().used.get(&Resource::QueueItems).map_or(0,|v|v.0);
 let receive=match receiver.receive(){Ok(QueueEvent::Data(row))=>serde_json::json!({"status":"data","row":row.payload()}),Ok(QueueEvent::End(v))=>serde_json::json!({"status":"end","success":v.is_ok()}),Err(e)=>serde_json::json!({"status":"error","error":e})};
 drop(receiver);let after=cancel.status().unwrap();
 println!("{}",serde_json::json!({"terminal":end,"status_before_receive":before,"queued_items_before_receive":queued,"received_rows_before_terminal":0,"receive_after_terminal":receive,"status_after_receiver_drop":after,"scope":"public low-level execute_into and bounded_channel combined by test sink; no production wire path"}));
}
