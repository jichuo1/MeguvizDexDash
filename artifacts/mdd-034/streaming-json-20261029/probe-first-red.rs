//! Bounded allocation observation of the real queue-producing path; never a performance claim.
use mdd_input::snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot};
use mdd_query::{budget::{bounded_channel,BudgetLimits,BudgetPool,BudgetScope,QueueEvent,Resource,RuntimeBudget},
    executor::{prepare,execute_into,Control,ExecutionLimits,ExecutionMode,FactSource,RelationSchema,facts::{MemoryCatalog,Table}},
    ir::{Bytes,Column,DataType,FactLayer,Node,QueryIr,Row,Value,IR_VERSION,TEXT_VERSION}};
use mdd_session::{Lifecycle,ResourceLimits};
use mdd_types::{Completeness,Coverage,DecimalU64,MddError,MddResult,result::{ResultIdentity,TerminalBuilder}};
use std::{alloc::{GlobalAlloc,Layout,System},cell::RefCell,collections::{BTreeMap,BTreeSet},path::PathBuf,
    sync::{Arc,atomic::{AtomicBool,AtomicUsize,Ordering}}};

struct AllocationObserver;
static TRACK:AtomicBool=AtomicBool::new(false);
static MAX_REQUEST:AtomicUsize=AtomicUsize::new(0);
unsafe impl GlobalAlloc for AllocationObserver {
    unsafe fn alloc(&self,layout:Layout)->*mut u8 {
        if TRACK.load(Ordering::SeqCst){MAX_REQUEST.fetch_max(layout.size(),Ordering::SeqCst);}
        unsafe{System.alloc(layout)}
    }
    unsafe fn dealloc(&self,ptr:*mut u8,layout:Layout){unsafe{System.dealloc(ptr,layout)}}
    unsafe fn realloc(&self,ptr:*mut u8,layout:Layout,size:usize)->*mut u8 {
        if TRACK.load(Ordering::SeqCst){MAX_REQUEST.fetch_max(size,Ordering::SeqCst);}
        unsafe{System.realloc(ptr,layout,size)}
    }
}
#[global_allocator] static ALLOC:AllocationObserver=AllocationObserver;

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

fn run(output_limit:u64,workspace_limit:u64)->serde_json::Value{
    let snapshot=Arc::new(Snapshot::capture(&[InputSpec{path:PathBuf::from("tests/fixtures/generated/minimal-035.dex"),kind:InputKind::RawDex,expected_sha256:None}],CaptureLimits::default()).unwrap());
    let snapshot_id=snapshot.manifest().snapshot_id.clone();let lifecycle=Lifecycle::new(ResourceLimits::default()).unwrap();
    let handle=lifecycle.register_snapshot(snapshot).unwrap();let session=lifecycle.open_session(&handle,ResourceLimits::default()).unwrap();
    let catalog=MemoryCatalog::new(snapshot_id.clone(),DecimalU64(0),BTreeMap::from([("rows".into(),Table{
        columns:vec![Column{id:"b".into(),display_name:"b".into(),data_type:DataType::Bytes,nullable:false}],
        required_layers:vec![FactLayer::Structure],rows:vec![]})]),BTreeSet::from([FactLayer::Structure])).unwrap();
    let source=OneRow{catalog,row:RefCell::new(Some(vec![Value::Bytes(Bytes(vec![0x5a;256*1024]))]))};
    let prepared=prepare(QueryIr{schema_version:IR_VERSION.into(),text_semantics:TEXT_VERSION.into(),snapshot_id:snapshot_id.clone(),
        catalog_epoch:DecimalU64(0),require_stable_order:false,root:Node::Scan{relation:"rows".into()}},&source).unwrap();
    let query=lifecycle.prepare_query(&session,prepared.runtime_binding().unwrap(),ResourceLimits::default()).unwrap();
    lifecycle.start_query(&session,&query,1).unwrap();let token=lifecycle.cancellation_token(&query).unwrap();
    let limits=BudgetLimits::default().with(Resource::OutputBytes,output_limit).with(Resource::QueryWorkspaceBytes,workspace_limit);
    let global=BudgetPool::global("output-observer".into(),limits.clone()).unwrap();
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
    MAX_REQUEST.store(0,Ordering::SeqCst);TRACK.store(true,Ordering::SeqCst);
    let result=execute_into(&prepared,&source,ExecutionMode::Streaming,&mut control,terminal,&sender);
    TRACK.store(false,Ordering::SeqCst);let max=MAX_REQUEST.load(Ordering::SeqCst);
    let mut pending=result.unwrap();
    let error=match receiver.receive().unwrap(){QueueEvent::End(Err(e))=>e, _=>panic!("low limit must fail before row delivery")};
    let mut receipt=receiver.into_delivery_receipt().unwrap();let final_result=receipt.finish(&mut pending).unwrap();
    serde_json::json!({"max_single_allocation_request":max,"queue_error":error,"terminal":final_result,
        "output_limit":output_limit,"workspace_limit":workspace_limit,"observed_after_track":"single-thread allocation requests during execute only"})
}
fn main(){
    let small_output=run(64,8192);let small_workspace=run(1024*1024,8192);
    println!("{}",serde_json::json!({"small_output":small_output,"small_workspace":small_workspace,
        "scope":"preallocated synthetic source Row; allocation request observation only, not RSS/performance/profile"}));
}
