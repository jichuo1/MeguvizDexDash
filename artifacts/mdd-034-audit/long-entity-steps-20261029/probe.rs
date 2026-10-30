//! Actual queue-consumer probe; generated long IDs are synthetic, not DEX identities.
use mdd_input::snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot};
use mdd_query::{budget::{bounded_channel,BudgetLimits,BudgetPool,BudgetScope,QueueEvent,Resource,RuntimeBudget},
    executor::{prepare,execute_into,Control,ExecutionLimits,ExecutionMode,FactSource,RelationSchema,facts::{MemoryCatalog,Table}},
    ir::{Column,DataType,FactLayer,Node,QueryIr,Row,Value,IR_VERSION,TEXT_VERSION}};
use mdd_session::{Lifecycle,ResourceLimits};
use mdd_types::{Completeness,Coverage,DecimalU64,MddError,MddResult,result::{ResultIdentity,TerminalBuilder}};
use std::{cell::RefCell,collections::{BTreeMap,BTreeSet},path::PathBuf,sync::Arc};

struct OneRow { catalog:MemoryCatalog, row:RefCell<Option<Row>> }
impl FactSource for OneRow {
    fn identity(&self)->&str{self.catalog.identity()}
    fn snapshot_id(&self)->&str{self.catalog.snapshot_id()}
    fn catalog_epoch(&self)->DecimalU64{self.catalog.catalog_epoch()}
    fn relation_schema(&self,r:&str)->MddResult<RelationSchema>{self.catalog.relation_schema(r)}
    fn require_layers(&self,l:&BTreeSet<FactLayer>)->MddResult<()>{self.catalog.require_layers(l)}
    fn validate_entity(&self,e:&mdd_facts::EntityRef)->MddResult<()>{self.catalog.validate_entity(e)}
    fn scan<'a>(&'a self,_:&str)->MddResult<Box<dyn Iterator<Item=MddResult<Row>>+'a>>{
        let row=self.row.borrow_mut().take().ok_or_else(||MddError::new(mdd_types::ErrorCode::InternalFault,"probe","row reused"))?;
        Ok(Box::new(std::iter::once(Ok(row))))
    }
    fn read_code_bytes(&self,e:&mdd_facts::EntityRef)->MddResult<Option<&[u8]>>{self.catalog.read_code_bytes(e)}
}

fn run(repeated:&str, count:usize)->serde_json::Value{
    let snapshot=Arc::new(Snapshot::capture(&[InputSpec{path:PathBuf::from("tests/fixtures/generated/minimal-035.dex"),kind:InputKind::RawDex,expected_sha256:None}],CaptureLimits::default()).unwrap());
    let snapshot_id=snapshot.manifest().snapshot_id.clone();let lifecycle=Lifecycle::new(ResourceLimits::default()).unwrap();
    let handle=lifecycle.register_snapshot(snapshot).unwrap();let session=lifecycle.open_session(&handle,ResourceLimits::default()).unwrap();
    let catalog=MemoryCatalog::new(snapshot_id.clone(),DecimalU64(0),BTreeMap::from([("rows".into(),Table{
        columns:vec![Column{id:"entity".into(),display_name:"entity".into(),data_type:DataType::Entity,nullable:false}],
        required_layers:vec![FactLayer::Structure],rows:vec![]})]),BTreeSet::from([FactLayer::Structure])).unwrap();
    let entity=mdd_facts::EntityRef{snapshot_id:snapshot_id.clone(),dex_occurrence_id:repeated.repeat(count),kind:mdd_facts::EntityKind::MethodDefinition,local_index:0};
    let source=OneRow{catalog,row:RefCell::new(Some(vec![Value::Entity(entity)]))};
    let prepared=prepare(QueryIr{schema_version:IR_VERSION.into(),text_semantics:TEXT_VERSION.into(),snapshot_id:snapshot_id.clone(),
        catalog_epoch:DecimalU64(0),require_stable_order:false,root:Node::Scan{relation:"rows".into()}},&source).unwrap();
    let query=lifecycle.prepare_query(&session,prepared.runtime_binding().unwrap(),ResourceLimits::default()).unwrap();
    lifecycle.start_query(&session,&query,1).unwrap();let token=lifecycle.cancellation_token(&query).unwrap();
    let limits=BudgetLimits::default().with(Resource::QuerySteps,64).with(Resource::OutputBytes,2*1024*1024).with(Resource::QueryWorkspaceBytes,2*1024*1024);
    let global=BudgetPool::global("entity-steps-observer".into(),limits.clone()).unwrap();
    let worker=global.child(token.worker_owner_id().unwrap(),BudgetScope::Worker,limits.clone()).unwrap();
    let session_pool=worker.child(session.id().into(),BudgetScope::Session,limits.clone()).unwrap();
    let pool=session_pool.child(query.id().into(),BudgetScope::Query,limits).unwrap();
    let runtime=RuntimeBudget::new(pool.clone(),token.clone()).unwrap();
    let terminal=TerminalBuilder::new(ResultIdentity{request_id:"observer".into(),operation:"query".into(),profile:"native-unqualified".into(),
        sql_dialect:None,session_id:Some(session.id().into()),snapshot_id:Some(snapshot_id),catalog_epoch:Some(DecimalU64(0)),
        query_id:Some(query.id().into()),schema_id:Some(prepared.runtime_binding().unwrap().schema_id)},
        Coverage{scope_id:"synthetic".into(),input:Completeness::Complete,facts:Completeness::Complete,required_layers:vec!["structure".into()],issues:vec![]}).unwrap();
    let (sender,mut receiver)=bounded_channel(pool.clone(),Some(token.clone()),2).unwrap();
    let mut control=Control::new(ExecutionLimits::default()).with_runtime(runtime);
    let mut pending=execute_into(&prepared,&source,ExecutionMode::Streaming,&mut control,terminal,&sender).unwrap();
    let mut rows=0;
    let end=loop{match receiver.receive().unwrap(){QueueEvent::Data(packet)=>{rows+=1;packet.acknowledge().unwrap();},QueueEvent::End(end)=>break end}};
    let error=end.err();let mut receipt=receiver.into_delivery_receipt().unwrap();let result=receipt.finish(&mut pending).unwrap();
    let used=pool.usage().unwrap().used.get(&Resource::QuerySteps).map_or(0,|v|v.0);
    serde_json::json!({"input_utf8_bytes":repeated.len()*count,"steps":used,"rows":rows,"queue_error":error,
        "operation_status":result.operation_status,"complete_result":result.is_complete_result(),"delivery_complete":token.status().unwrap().delivery_complete})
}
fn main(){
    let plain=run("x",500_000);let escaped=run("\"",500_000);
    println!("{}",serde_json::json!({"plain":plain,"escaped":escaped,"scope":"synthetic SDK provider and real query-bound queue; no HostLab/profile claim"}));
}
