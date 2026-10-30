use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{archive::{ArchiveInventory,ArchiveLimits,InventoryPolicy},
    snapshot::{CaptureLimits,InputKind,InputSpec,Snapshot}};
use mdd_query::budget::{BudgetLimits,BudgetPool,BudgetScope,Resource,RuntimeBudget};
use mdd_session::{Lifecycle,ResourceLimits};
use mdd_sql::{SqlBridge,control::{SqlControl,SqlLimits},dialects::SqlDialect,
    provider::metadata::MetadataSqlProvider,values::{SqlText,SqlValue}};
use mdd_types::DecimalU64;
use serde_json::{Value,json};
use std::{path::PathBuf,sync::Arc,time::{Duration,Instant}};

fn setup(dialect:SqlDialect)->(Lifecycle,mdd_session::SessionHandle,SqlBridge){
    let snapshot=Arc::new(Snapshot::capture(&[InputSpec{
        path:PathBuf::from("tests/fixtures/references/generated/classic-035.dex"),kind:InputKind::RawDex,
        expected_sha256:Some("076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8".into()),
    }],CaptureLimits::default()).unwrap());
    let inv=ArchiveInventory::build(&snapshot.sources()[0],InventoryPolicy::default(),ArchiveLimits::default()).unwrap();
    let facts=Arc::new(MetadataFacts::build(&snapshot,&inv,0,StringLimits::default()).unwrap());
    let bridge=SqlBridge::new(Arc::new(MetadataSqlProvider::new(vec![facts],DecimalU64(0)).unwrap()),
        dialect,SqlLimits::default()).unwrap();
    let life=Lifecycle::new(ResourceLimits::default()).unwrap();let snap=life.register_snapshot(snapshot).unwrap();
    let session=life.open_session(&snap,ResourceLimits::default()).unwrap();(life,session,bridge)
}

fn run(dialect:SqlDialect,operator:&str,case:&str)->Value{
    let (life,session,bridge)=setup(dialect);
    let length=match case{"low"=>50_000,"long_ok"=>10_000,"cancel_observed"=>300_000,_=>0};
    let value=match case{
        "low"|"long_ok"|"cancel_observed"=>SqlValue::text(&if operator=="lower"{"A".repeat(length)}else{"a".repeat(length)}),
        "ascii"=>SqlValue::text("AbC"),"empty"=>SqlValue::text(""),"null"=>SqlValue::Null,
        "nul"=>SqlValue::text("A\0a"),"non_ascii"=>SqlValue::text("AzÄß"),
        "non_scalar"=>SqlValue::Text(SqlText{utf16:vec![0x41,0,0xd800,0x61,0xdc00],original_mutf8:None}),
        "cancel_before"=>SqlValue::text("AbC"),_=>unreachable!(),
    };
    let sql=format!("SELECT {operator}(?) AS v");
    let prepared=bridge.prepare_with_parameters(&sql,&[value]).unwrap();
    let query=life.prepare_query(&session,prepared.runtime_query_binding().unwrap(),ResourceLimits::default()).unwrap();
    life.start_query(&session,&query,1).unwrap();let token=life.cancellation_token(&query).unwrap();
    let mut limits=BudgetLimits::default();
    if case=="low"{limits=limits.with(Resource::QuerySteps,64);}
    let root=BudgetPool::global("case-independent-root".into(),limits.clone()).unwrap();
    let worker=root.child(token.worker_owner_id().unwrap(),BudgetScope::Worker,limits.clone()).unwrap();
    let session_pool=worker.child(session.id().into(),BudgetScope::Session,limits.clone()).unwrap();
    let pool=session_pool.child(query.id().into(),BudgetScope::Query,limits).unwrap();
    let runtime=RuntimeBudget::new(pool.clone(),token.clone()).unwrap();
    let bound=prepared.bind_runtime(&runtime).unwrap();
    let used=|resource|pool.usage().unwrap().used.get(&resource).map_or(0,|x|x.0);
    if case=="cancel_observed"{
        let handle=std::thread::spawn(move || bound.execute(SqlControl::new(SqlLimits::default(),None).with_runtime(runtime)));
        let deadline=Instant::now()+Duration::from_secs(10);let mut observed=0;
        loop{
            let n=used(Resource::QuerySteps);if n>5000{observed=n;break;}
            if handle.is_finished()||Instant::now()>=deadline{break;}
            std::thread::yield_now();
        }
        token.cancel().unwrap();let result=handle.join().unwrap();
        return json!({"case":case,"operator":operator,"observed_steps_before_cancel":observed,
            "result":match result{Ok(v)=>json!({"status":"ok","rows":v.rows()}),Err(e)=>json!({"status":"error","error":e})},
            "used_workspace_after":used(Resource::QueryWorkspaceBytes),"execution_complete":token.status().unwrap().execution_complete});
    }
    if case=="cancel_before"{token.cancel().unwrap();}
    let result=bound.execute(SqlControl::new(SqlLimits::default(),None).with_runtime(runtime));
    match result{
        Ok(result)=>{
            let rows=if case=="long_ok"{
                match &result.rows()[0][0]{
                    SqlValue::Text(t)=>json!({"unit_count":t.utf16.len(),"all_expected":t.utf16.iter().all(|v|
                        *v==if operator=="lower"{u16::from(b'a')}else{u16::from(b'A')}),"original_mutf8":t.original_mutf8}),
                    other=>json!({"unexpected":other}),
                }
            }else{json!(result.rows())};
            let complete=result.calculation_complete();let held=used(Resource::QueryWorkspaceBytes);drop(result);
            json!({"case":case,"operator":operator,"status":"ok","rows":rows,"calculation_complete":complete,
                "execution_complete":token.status().unwrap().execution_complete,"workspace_held":held,
                "workspace_after_drop":used(Resource::QueryWorkspaceBytes)})
        }
        Err(error)=>json!({"case":case,"operator":operator,"status":"error","error":error,
            "execution_complete":token.status().unwrap().execution_complete,
            "workspace_after":used(Resource::QueryWorkspaceBytes)}),
    }
}

fn main(){
    let mut records=Vec::new();
    for (name,dialect) in [("native",SqlDialect::NativeV1),("010",SqlDialect::DexSql010),("011",SqlDialect::DexSql011)]{
        for operator in ["lower","upper"]{
            for case in ["low","long_ok","ascii","empty","null","nul","non_ascii","non_scalar","cancel_before","cancel_observed"]{
                records.push(json!({"dialect":name,"result":run(dialect,operator,case)}));
            }
        }
    }
    println!("{}",json!({"records":records,"profile_admitted":false,
        "scope":"real synthetic snapshot/session/runtime; SQLite allocations and decoded input copies not measured"}));
}
