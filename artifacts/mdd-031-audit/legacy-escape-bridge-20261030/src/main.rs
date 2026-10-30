//! Independent public SQL bridge probe; synthetic data and no profile admission.
use mdd_sql::{SqlBridge, control::{SqlControl,SqlLimits}, dialects::SqlDialect,
    provider::{SqlBinding,SqlFactCursor,SqlFactProvider,SqlRelation}};
use mdd_types::{DecimalU64,ErrorCode,MddError,MddResult};
use serde_json::{json,Value};
use std::sync::Arc;

struct Empty(SqlBinding);
impl SqlFactProvider for Empty {
    fn binding(&self)->&SqlBinding { &self.0 }
    fn relations(&self)->MddResult<Vec<SqlRelation>> { Ok(vec![]) }
    fn require_relation(&self,_:&str)->MddResult<()> {
        Err(MddError::new(ErrorCode::InvalidArgument,"fixture","unexpected relation"))
    }
    fn open_cursor(self:Arc<Self>,_:&str,_:SqlControl)->MddResult<Box<dyn SqlFactCursor>> {
        Err(MddError::new(ErrorCode::InvalidArgument,"fixture","unexpected cursor"))
    }
}
fn execute(dialect:SqlDialect,sql:&str,mode:&str)->Value {
    let provider=Arc::new(Empty(SqlBinding{provider_identity:"synthetic-escape".into(),snapshot_id:"fixture-only".into(),catalog_epoch:DecimalU64(0)}));
    let limits=if mode=="low" { SqlLimits{max_steps:1,..SqlLimits::default()} } else { SqlLimits::default() };
    let bridge=SqlBridge::new(provider,dialect,limits).unwrap();
    let prepared=match bridge.prepare(sql) { Ok(value)=>value, Err(error)=>return json!({"status":"prepare_error","error":error}) };
    let control=SqlControl::new(limits,None);
    if mode=="cancelled" {control.cancel().unwrap();}
    match bridge.execute(&prepared,control) {
        Ok(result)=>json!({"status":"ok","result":result}),
        Err(error)=>json!({"status":"error","error":error}),
    }
}
fn main() {
    let cases=[
        ("dangling_like","SELECT 'a' LIKE 'a!' ESCAPE '!' AS result","normal"),
        ("dangling_not_like","SELECT 'a' NOT LIKE 'a!' ESCAPE '!' AS result","normal"),
        ("escaped_literal","SELECT 'a!' LIKE 'a!!' ESCAPE '!' AS result","normal"),
        ("null_like","SELECT NULL LIKE 'a!' ESCAPE '!' AS result","normal"),
        ("null_escape","SELECT 'a' LIKE 'a!' ESCAPE NULL AS result","normal"),
        ("low_budget","SELECT 'a' LIKE 'a!' ESCAPE '!' AS result","low"),
        ("cancel_before","SELECT 'a' LIKE 'a!' ESCAPE '!' AS result","cancelled"),
    ];
    let mut records=Vec::new();
    for (name,dialect) in [("native",SqlDialect::NativeV1),("010",SqlDialect::DexSql010),("011",SqlDialect::DexSql011)] {
        for (case,sql,mode) in cases {
            records.push(json!({"dialect":name,"case":case,"sql":sql,"result":execute(dialect,sql,mode)}));
        }
    }
    println!("{}",json!({"records":records,"scope":"synthetic public SQL bridge, no worker or profile qualification","profile_admitted":false}));
}
