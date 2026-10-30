use mdd_input::snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot};
use mdd_query::budget::{BudgetLimits,BudgetPool,BudgetScope,Resource,RuntimeBudget};
use mdd_session::{Lifecycle,ResourceLimits};
use mdd_sql::{SqlBridge,control::{SqlControl,SqlLimits},dialects::SqlDialect,provider::{SqlBinding,SqlColumn,SqlFactCursor,SqlFactProvider,SqlRelation,SqlRow},values::{SqlType,SqlValue}};
use mdd_types::{DecimalU64,MddResult};
use std::{path::PathBuf,sync::Arc,time::{Duration,Instant}};

struct Provider{binding:SqlBinding,n:usize}
struct Cursor{rows:std::vec::IntoIter<SqlRow>}
impl SqlFactCursor for Cursor{fn next_row(&mut self)->MddResult<Option<SqlRow>>{Ok(self.rows.next())}}
impl SqlFactProvider for Provider{
 fn binding(&self)->&SqlBinding{&self.binding}
 fn relations(&self)->MddResult<Vec<SqlRelation>>{
  Ok(vec![SqlRelation{name:"key_values".into(),columns:vec![
   SqlColumn{id:"id".into(),name:"id".into(),data_type:SqlType::U64,nullable:false},
   SqlColumn{id:"t".into(),name:"t".into(),data_type:SqlType::Text,nullable:false},
   SqlColumn{id:"b".into(),name:"b".into(),data_type:SqlType::Bytes,nullable:false}],required_layers:vec![],estimated_rows:Some(DecimalU64(2))}])
 }
 fn require_relation(&self,_:&str)->MddResult<()>{Ok(())}
 fn open_cursor(self:Arc<Self>,_:&str,_:SqlControl)->MddResult<Box<dyn SqlFactCursor>>{
  let rows=(0..2).map(|i|vec![SqlValue::U64(DecimalU64(i)),SqlValue::text(&(if i==0{"B"}else{"A"}).repeat(self.n)),SqlValue::Bytes(vec![if i==0{b'B'}else{b'A'};self.n])]).collect::<Vec<_>>();
  Ok(Box::new(Cursor{rows:rows.into_iter()}))
 }
}
fn used(pool:&BudgetPool)->u64{pool.usage().unwrap().used.get(&Resource::QueryWorkspaceBytes).map_or(0,|x|x.0)}
fn run(d:SqlDialect,name:&str,sql:&str,n:usize,budget:u64,mode:&str)->serde_json::Value{
 let snapshot=Arc::new(Snapshot::capture(&[InputSpec{path:PathBuf::from("handoff/key-lease-cebb3a7-20261029/tests/fixtures/references/generated/classic-035.dex"),kind:InputKind::RawDex,expected_sha256:Some("076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8".into())}],CaptureLimits::default()).unwrap());
 let p=Arc::new(Provider{binding:SqlBinding{provider_identity:"key-lease-probe".into(),snapshot_id:snapshot.manifest().snapshot_id.clone(),catalog_epoch:DecimalU64(0)},n});
 let bridge=SqlBridge::new(p,d,SqlLimits::default()).unwrap();let prep=bridge.prepare(sql).unwrap();
 let life=Lifecycle::new(ResourceLimits::default()).unwrap();let sh=life.register_snapshot(snapshot).unwrap();let session=life.open_session(&sh,ResourceLimits::default()).unwrap();
 let query=life.prepare_query(&session,prep.runtime_query_binding().unwrap(),ResourceLimits::default()).unwrap();life.start_query(&session,&query,1).unwrap();let cancel=life.cancellation_token(&query).unwrap();
 let limits=BudgetLimits::default().with(Resource::QueryWorkspaceBytes,budget);let global=BudgetPool::global("key-lease-root".into(),limits.clone()).unwrap();
 let worker=global.child(cancel.worker_owner_id().unwrap(),BudgetScope::Worker,limits.clone()).unwrap();let sess=worker.child(session.id().into(),BudgetScope::Session,limits.clone()).unwrap();
 let pool=sess.child(query.id().into(),BudgetScope::Query,limits).unwrap();let runtime=RuntimeBudget::new(pool.clone(),cancel.clone()).unwrap();let bound=prep.bind_runtime(&runtime).unwrap();
 if mode=="during" {
  let job=std::thread::spawn(move||bound.execute(SqlControl::new(SqlLimits::default(),None).with_runtime(runtime)));let until=Instant::now()+Duration::from_secs(10);let mut observed=0;
  loop{let current=used(&pool);if current>100_000{observed=current;break}if job.is_finished()||Instant::now()>=until{break}std::thread::yield_now()}
  cancel.cancel().unwrap();let out=job.join().unwrap();return serde_json::json!({"dialect":format!("{d:?}"),"case":name,"observed_workspace":observed,"outcome":match out{Ok(x)=>serde_json::json!({"status":"ok","rows":x.rows()}),Err(e)=>serde_json::json!({"status":"error","error":e})},"used_after":used(&pool),"execution_complete":cancel.status().unwrap().execution_complete});
 }
 if mode=="before" {cancel.cancel().unwrap();}
 match bound.execute(SqlControl::new(SqlLimits::default(),None).with_runtime(runtime)){
  Ok(x)=>{let held=used(&pool);let rows=serde_json::to_value(x.rows()).unwrap();let complete=x.calculation_complete();drop(x);serde_json::json!({"dialect":format!("{d:?}"),"case":name,"status":"ok","rows":rows,"complete":complete,"used_with_result":held,"used_after_drop":used(&pool)})},
  Err(e)=>serde_json::json!({"dialect":format!("{d:?}"),"case":name,"status":"error","error":e,"used_after":used(&pool),"execution_complete":cancel.status().unwrap().execution_complete})
 }
}
fn main(){let mut rows=Vec::new();for d in [SqlDialect::NativeV1,SqlDialect::DexSql010,SqlDialect::DexSql011]{
 let cases=[("text_distinct","SELECT COUNT(DISTINCT t) FROM key_values"),("bytes_distinct","SELECT COUNT(DISTINCT b) FROM key_values"),
 ("text_group","SELECT COUNT(*) FROM key_values GROUP BY t"),("bytes_group","SELECT COUNT(*) FROM key_values GROUP BY b"),
 ("text_order","SELECT id FROM key_values ORDER BY t"),("bytes_order","SELECT id FROM key_values ORDER BY b")];
 for(name,sql) in cases{rows.push(run(d,&format!("{name}_low"),sql,10_000,8192,"normal"));rows.push(run(d,&format!("{name}_high"),sql,10_000,200_000,"normal"));}
 for(name,sql) in [("text_order","SELECT id FROM key_values ORDER BY t"),("bytes_order","SELECT id FROM key_values ORDER BY b")]{
  rows.push(run(d,&format!("{name}_cancel_before"),sql,10_000,200_000,"before"));
  rows.push(run(d,&format!("{name}_cancel_observed"),sql,300_000,4_000_000,"during"));
 }
}println!("{}",serde_json::json!({"records":rows,"profile_admitted":false,"scope":"independent snapshot-bound synthetic provider; logical key buffers only"}));}
