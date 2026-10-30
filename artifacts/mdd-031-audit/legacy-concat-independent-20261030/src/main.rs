use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{archive::{ArchiveInventory,ArchiveLimits,InventoryPolicy},snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot}};
use mdd_query::budget::{BudgetLimits,BudgetPool,BudgetScope,Resource,RuntimeBudget};
use mdd_session::{Lifecycle,ResourceLimits,SessionHandle,cancellation::QueryCancellation};
use mdd_sql::{SqlBridge,PreparedSql,control::{SqlControl,SqlLimits},dialects::SqlDialect,provider::metadata::MetadataSqlProvider,values::SqlValue};
use mdd_types::DecimalU64;
use serde_json::{json,Value};
use std::{path::PathBuf,sync::Arc,time::{Duration,Instant}};

fn setup(dialect:SqlDialect)->(Lifecycle,SessionHandle,SqlBridge){
 let snapshot=Arc::new(Snapshot::capture(&[InputSpec{path:PathBuf::from("tests/fixtures/generated/strings-mutf8-035.dex"),kind:InputKind::RawDex,expected_sha256:Some("4deab5f75b23c118b170005d89a6ebc0d18d894383280253e70de0507d260f35".into())}],CaptureLimits::default()).unwrap());
 let inventory=ArchiveInventory::build(&snapshot.sources()[0],InventoryPolicy::default(),ArchiveLimits::default()).unwrap();
 let facts=Arc::new(MetadataFacts::build(&snapshot,&inventory,0,StringLimits::default()).unwrap());
 let bridge=SqlBridge::new(Arc::new(MetadataSqlProvider::new(vec![facts],DecimalU64(0)).unwrap()),dialect,SqlLimits::default()).unwrap();
 let life=Lifecycle::new(ResourceLimits::default()).unwrap();let snap=life.register_snapshot(snapshot).unwrap();let session=life.open_session(&snap,ResourceLimits::default()).unwrap();(life,session,bridge)
}
fn runtime(life:&Lifecycle,session:&SessionHandle,p:&PreparedSql,steps:u64)->(RuntimeBudget,QueryCancellation){
 let query=life.prepare_query(session,p.runtime_query_binding().unwrap(),ResourceLimits::default()).unwrap();life.start_query(session,&query,1).unwrap();let token=life.cancellation_token(&query).unwrap();
 let limits=BudgetLimits::default().with(Resource::QueryWorkspaceBytes,2_000_000).with(Resource::QuerySteps,steps);
 let root=BudgetPool::global("concat-audit".into(),limits.clone()).unwrap();let worker=root.child(token.worker_owner_id().unwrap(),BudgetScope::Worker,limits.clone()).unwrap();let session_pool=worker.child(session.id().into(),BudgetScope::Session,limits.clone()).unwrap();let query_pool=session_pool.child(query.id().into(),BudgetScope::Query,limits).unwrap();
 (RuntimeBudget::new(query_pool,token.clone()).unwrap(),token)
}
fn used(pool:&BudgetPool,r:Resource)->u64{pool.usage().unwrap().used.get(&r).map_or(0,|v|v.0)}
fn run(dialect:SqlDialect,name:&str,sql:&str,values:Vec<SqlValue>,steps:u64,mode:&str)->Value{
 let(life,session,bridge)=setup(dialect);let p=match bridge.prepare_with_parameters(sql,&values){Ok(p)=>p,Err(e)=>return json!({"case":name,"status":"prepare_error","error":e})};
 let(runtime,token)=runtime(&life,&session,&p,steps);let pool=runtime.pool().clone();let bound=p.bind_runtime(&runtime).unwrap();
 if mode=="during"{
  let task=std::thread::spawn(move||bound.execute(SqlControl::new(SqlLimits::default(),None).with_runtime(runtime)));
  let deadline=Instant::now()+Duration::from_secs(10);let mut observed=0;
  loop{let n=used(&pool,Resource::QuerySteps);if n>5000{observed=n;break}if task.is_finished()||Instant::now()>=deadline{break}std::thread::yield_now()}
  token.cancel().unwrap();let outcome=task.join().unwrap();return json!({"case":name,"status":"observed_cancel","observed_steps":observed,"outcome":match outcome{Ok(v)=>json!({"status":"ok","rows":v.rows()}),Err(e)=>json!({"status":"error","error":e})},"used_after":used(&pool,Resource::QueryWorkspaceBytes),"execution_complete":token.status().unwrap().execution_complete});
 }
 if mode=="before"{token.cancel().unwrap();}
 match bound.execute(SqlControl::new(SqlLimits::default(),None).with_runtime(runtime)){
  Ok(result)=>{let held=used(&pool,Resource::QueryWorkspaceBytes);let rows=serde_json::to_value(result.rows()).unwrap();let complete=result.calculation_complete();drop(result);json!({"case":name,"status":"ok","rows":rows,"complete":complete,"used_with_result":held,"used_after":used(&pool,Resource::QueryWorkspaceBytes)})},
  Err(error)=>json!({"case":name,"status":"error","error":error,"used_after":used(&pool,Resource::QueryWorkspaceBytes),"execution_complete":token.status().unwrap().execution_complete}),
 }
}
fn main(){
 let cases=[
 ("ascii","x'41'||x'42'",None),("valid_utf8","x'C3A9'||x'41'",None),("split_utf8","x'C3'||x'A9'",None),
 ("split_supplementary","x'F09F'||x'9880'",None),("truncated_prefix","x'E282'||x'41'",None),
 ("invalid_continuation","x'C341'||x'42'",None),("two_invalid","x'FF'||x'FF'",None),
 ("overlong_nul","x'C080'||x'41'",None),("blob_text","x'41'||'B'",None),("text_blob","'B'||x'41'",None),
 ("blob_unicode_text","x'41'||'中'",None),("null_right","x'41'||NULL",None),("null_left","NULL||x'41'",None),
 ("source_nul","s.value||x'41'",Some(1)),("source_surrogate","s.value||x'41'",Some(4)),("source_pair","s.value||x'41'",Some(5))];
 let mut records=Vec::new();
 for(dname,dialect)in [("native",SqlDialect::NativeV1),("A0",SqlDialect::DexSql010),("A1",SqlDialect::DexSql011)]{
  for(name,expression,index)in cases{
   let suffix=index.map_or(String::new(),|n|format!(" FROM native_strings AS s WHERE s.string_idx={n}"));
   let sql=format!("SELECT {expression} AS value,hex({expression}) AS value_hex{suffix}");let result=run(dialect,name,&sql,vec![],1_000_000,"normal");records.push(json!({"dialect":dname,"sql":sql,"result":result}));
  }
  for(kind,left,right)in [("text",SqlValue::text(&"A".repeat(50_000)),SqlValue::text("z")),("bytes",SqlValue::Bytes(vec![0x41;50_000]),SqlValue::Bytes(vec![0xff]))]{
   let sql="SELECT CASE WHEN ? || ? IS NULL THEN 1 ELSE 0 END";
   for(mode,steps,control)in [("low",64,"normal"),("high",1_000_000,"normal"),("pre_cancel",1_000_000,"before"),("observed_cancel",1_000_000,"during")]{
    let name=format!("{kind}_{mode}");let result=run(dialect,&name,sql,vec![left.clone(),right.clone()],steps,control);records.push(json!({"dialect":dname,"sql":sql,"result":result}));
   }
  }
 }
 println!("{}",json!({"records":records,"profile_admitted":false,"scope":"synthetic DEX public bridge, no worker or performance qualification"}));
}
