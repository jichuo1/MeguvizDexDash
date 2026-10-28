use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{archive::{ArchiveInventory,ArchiveLimits,InventoryPolicy},snapshot::{Snapshot,CaptureLimits,InputKind,InputSpec}};
use mdd_query::budget::{BudgetLimits,BudgetPool,BudgetScope,Resource,RuntimeBudget};
use mdd_session::{Lifecycle,ResourceLimits,SessionHandle};
use mdd_sql::{SqlBridge,PreparedSql,control::{SqlControl,SqlLimits},dialects::SqlDialect,provider::metadata::MetadataSqlProvider};
use mdd_types::DecimalU64;
use std::{path::PathBuf,sync::Arc};

fn runtime(lifecycle:&Lifecycle,session:&SessionHandle,prepared:&PreparedSql,limit:u64)->(RuntimeBudget,BudgetPool){
    let q=lifecycle.prepare_query(session,prepared.runtime_query_binding().unwrap(),ResourceLimits::default()).unwrap();
    lifecycle.start_query(session,&q,1).unwrap();
    let token=lifecycle.cancellation_token(&q).unwrap();
    let limits=BudgetLimits::default().with(Resource::QueryWorkspaceBytes,limit);
    let root=BudgetPool::global(format!("root-{}",q.id()),limits.clone()).unwrap();
    let worker=root.child(token.worker_owner_id().unwrap(),BudgetScope::Worker,limits.clone()).unwrap();
    let sb=worker.child(session.id().into(),BudgetScope::Session,limits.clone()).unwrap();
    let pool=sb.child(q.id().into(),BudgetScope::Query,limits).unwrap();
    (RuntimeBudget::new(pool.clone(),token).unwrap(),pool)
}
fn used(pool:&BudgetPool)->u64{pool.usage().unwrap().used.get(&Resource::QueryWorkspaceBytes).map_or(0,|value|value.0)}
fn main(){
    let path=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures/references/generated/classic-035.dex");
    let snap=Arc::new(Snapshot::capture(&[InputSpec{path,kind:InputKind::RawDex,expected_sha256:None}],CaptureLimits::default()).unwrap());
    let inv=ArchiveInventory::build(&snap.sources()[0],InventoryPolicy::default(),ArchiveLimits::default()).unwrap();
    let facts=Arc::new(MetadataFacts::build(&snap,&inv,0,StringLimits::default()).unwrap());
    let bridge=SqlBridge::new(Arc::new(MetadataSqlProvider::new(vec![facts],DecimalU64(0)).unwrap()),SqlDialect::NativeV1,SqlLimits::default()).unwrap();
    let lifecycle=Lifecycle::new(ResourceLimits::default()).unwrap();
    let sh=lifecycle.register_snapshot(snap).unwrap();
    let session=lifecycle.open_session(&sh,ResourceLimits::default()).unwrap();
    let prep=bridge.prepare("SELECT 1 AS long_alias WHERE 0").unwrap();
    let (rt,pool)=runtime(&lifecycle,&session,&prep,0);
    let outcome=prep.bind_runtime(&rt).unwrap().execute(SqlControl::new(SqlLimits::default(),None).with_runtime(rt));
    let zero=match outcome {Ok(r)=>serde_json::json!({"status":"ok","columns":r.columns(),"rows":r.rows().len(),"workspace":used(&pool)}),Err(e)=>serde_json::json!({"status":"error","error":e,"workspace":used(&pool)})};
    let prep=bridge.prepare("SELECT 1 AS long_alias WHERE 0").unwrap();
    let (rt,pool)=runtime(&lifecycle,&session,&prep,65536);
    let result=prep.bind_runtime(&rt).unwrap().execute(SqlControl::new(SqlLimits::default(),None).with_runtime(rt)).unwrap();
    let during=used(&pool); let columns=result.columns().to_vec(); let rows=result.rows().len(); drop(result);
    let metadata=serde_json::json!({"columns":columns,"rows":rows,"workspace_during":during,"workspace_after_drop":used(&pool)});
    let prep=bridge.prepare("SELECT 'persistent copy'").unwrap();
    let (rt,pool)=runtime(&lifecycle,&session,&prep,65536);
    let result=prep.bind_runtime(&rt).unwrap().execute(SqlControl::new(SqlLimits::default(),None).with_runtime(rt)).unwrap();
    let during=used(&pool); let copied=result.rows().to_vec(); drop(result);
    let after=used(&pool);
    println!("{}",serde_json::json!({"zero_row":zero,"metadata":metadata,"clone":{"workspace_during":during,"workspace_after_drop":after,"copied_rows":copied.len(),"copy":copied}}));
}
