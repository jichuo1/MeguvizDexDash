use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{archive::{ArchiveInventory,ArchiveLimits,InventoryPolicy},snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot}};
use mdd_query::budget::{BudgetLimits,BudgetPool,BudgetScope,Resource,RuntimeBudget};
use mdd_session::{Lifecycle,ResourceLimits,SessionHandle,cancellation::QueryCancellation};
use mdd_sql::{SqlBridge,PreparedSql,control::{SqlControl,SqlLimits},dialects::SqlDialect,provider::metadata::MetadataSqlProvider,values::{SqlValue,SqlText}};
use mdd_types::DecimalU64;
use serde_json::{Value,json};
use std::{path::PathBuf,sync::Arc,time::{Duration,Instant}};

fn setup(dialect:SqlDialect)->(Lifecycle,SessionHandle,SqlBridge){
    let snapshot=Arc::new(Snapshot::capture(&[InputSpec{path:PathBuf::from("handoff/concat-3c334c5-20261029/tests/fixtures/references/generated/classic-035.dex"),kind:InputKind::RawDex,expected_sha256:Some("076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8".into())}],CaptureLimits::default()).unwrap());
    let inventory=ArchiveInventory::build(&snapshot.sources()[0],InventoryPolicy::default(),ArchiveLimits::default()).unwrap();
    let facts=Arc::new(MetadataFacts::build(&snapshot,&inventory,0,StringLimits::default()).unwrap());
    let bridge=SqlBridge::new(Arc::new(MetadataSqlProvider::new(vec![facts],DecimalU64(0)).unwrap()),dialect,SqlLimits::default()).unwrap();
    let life=Lifecycle::new(ResourceLimits::default()).unwrap();
    let snap=life.register_snapshot(snapshot).unwrap();
    let session=life.open_session(&snap,ResourceLimits::default()).unwrap();
    (life,session,bridge)
}
fn runtime(life:&Lifecycle,session:&SessionHandle,prepared:&PreparedSql,bytes:u64,steps:u64)->(RuntimeBudget,QueryCancellation){
    let query=life.prepare_query(session,prepared.runtime_query_binding().unwrap(),ResourceLimits::default()).unwrap();
    life.start_query(session,&query,1).unwrap();let token=life.cancellation_token(&query).unwrap();
    let limits=BudgetLimits::default().with(Resource::QueryWorkspaceBytes,bytes).with(Resource::QuerySteps,steps);
    let root=BudgetPool::global("concat-independent".into(),limits.clone()).unwrap();
    let worker=root.child(token.worker_owner_id().unwrap(),BudgetScope::Worker,limits.clone()).unwrap();
    let session_pool=worker.child(session.id().into(),BudgetScope::Session,limits.clone()).unwrap();
    let query_pool=session_pool.child(query.id().into(),BudgetScope::Query,limits).unwrap();
    (RuntimeBudget::new(query_pool,token.clone()).unwrap(),token)
}
fn used(pool:&BudgetPool)->u64{pool.usage().unwrap().used.get(&Resource::QueryWorkspaceBytes).map_or(0,|v|v.0)}
fn run(dialect:SqlDialect,name:&str,sql:&str,values:Vec<SqlValue>,bytes:u64,steps:u64,mode:&str)->Value{
    let(life,session,bridge)=setup(dialect);
    let p=bridge.prepare_with_parameters(sql,&values).unwrap();let(runtime,token)=runtime(&life,&session,&p,bytes,steps);
    let pool=runtime.pool().clone();let bound=p.bind_runtime(&runtime).unwrap();
    if mode=="during" {
        let task=std::thread::spawn(move||bound.execute(SqlControl::new(SqlLimits::default(),None).with_runtime(runtime)));
        let deadline=Instant::now()+Duration::from_secs(10);let mut observed=0;
        loop {let n=pool.usage().unwrap().used.get(&Resource::QuerySteps).map_or(0,|v|v.0);if n>5000{observed=n;break}if task.is_finished()||Instant::now()>=deadline{break}std::thread::yield_now()}
        token.cancel().unwrap();let result=task.join().unwrap();
        return json!({"dialect":format!("{dialect:?}"),"case":name,"observed_steps":observed,"result":match result{Ok(v)=>json!({"status":"ok","rows":v.rows()}),Err(e)=>json!({"status":"error","error":e})},"used_after":used(&pool),"execution_complete":token.status().unwrap().execution_complete});
    }
    if mode=="before"{token.cancel().unwrap();}
    match bound.execute(SqlControl::new(SqlLimits::default(),None).with_runtime(runtime)){
        Ok(result)=>{let held=used(&pool);let rows=serde_json::to_value(result.rows()).unwrap();let complete=result.calculation_complete();drop(result);json!({"dialect":format!("{dialect:?}"),"case":name,"status":"ok","rows":rows,"complete":complete,"used_with_result":held,"used_after_drop":used(&pool)})},
        Err(error)=>json!({"dialect":format!("{dialect:?}"),"case":name,"status":"error","error":error,"used_after":used(&pool),"execution_complete":token.status().unwrap().execution_complete}),
    }
}
fn main(){let mut rows=Vec::new();for d in [SqlDialect::NativeV1,SqlDialect::DexSql010,SqlDialect::DexSql011]{
 let text=|v:Vec<u16>|SqlValue::Text(SqlText{utf16:v,original_mutf8:None});
 let cases=[("ascii",vec![SqlValue::text("A"),SqlValue::text("B")]),("empty",vec![SqlValue::text(""),SqlValue::text("")]),
 ("null_left",vec![SqlValue::Null,SqlValue::text("B")]),("null_right",vec![SqlValue::text("A"),SqlValue::Null]),
 ("nul",vec![text(vec![65,0]),SqlValue::text("B")]),("unpaired",vec![text(vec![0xd800]),SqlValue::text("B")]),
 ("pair",vec![text(vec![0xd83d,0xde00]),SqlValue::text("B")]),("bytes",vec![SqlValue::Bytes(vec![0,0xff]),SqlValue::Bytes(vec![0x41])])];
 for(name,values) in cases{rows.push(run(d,name,"SELECT ? || ? AS v",values,1_000_000,1_000_000,"normal"));}
 for(kind,left,right) in [("text",SqlValue::text(&"A".repeat(50_000)),SqlValue::text("z")),("bytes",SqlValue::Bytes(vec![0x41;50_000]),SqlValue::Bytes(vec![0xff]))]{
  rows.push(run(d,&format!("{kind}_low"),"SELECT CASE WHEN ? || ? IS NULL THEN 1 ELSE 0 END",vec![left.clone(),right.clone()],1_000_000,64,"normal"));
  rows.push(run(d,&format!("{kind}_high"),"SELECT CASE WHEN ? || ? IS NULL THEN 1 ELSE 0 END",vec![left,right],1_000_000,1_000_000,"normal"));
 }
 for(kind,left,right) in [("text",SqlValue::text(&"A".repeat(200_000)),SqlValue::text("z")),("bytes",SqlValue::Bytes(vec![0x41;200_000]),SqlValue::Bytes(vec![0xff]))]{
  rows.push(run(d,&format!("{kind}_pre_cancel"),"SELECT CASE WHEN ? || ? IS NULL THEN 1 ELSE 0 END",vec![left.clone(),right.clone()],1_000_000,1_000_000,"before"));
  rows.push(run(d,&format!("{kind}_observed_cancel"),"SELECT CASE WHEN ? || ? IS NULL THEN 1 ELSE 0 END",vec![left,right],1_000_000,1_000_000,"during"));
 }
}println!("{}",json!({"cases":rows,"profiles_admitted":false,"scope":"isolated source synthetic bound SQL sessions; no transport or profile proof"}));}
