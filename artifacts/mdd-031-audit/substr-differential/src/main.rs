use mdd_sql::{SqlBridge, control::{SqlControl,SqlLimits}, dialects::SqlDialect, provider::{SqlBinding,SqlFactCursor,SqlFactProvider,SqlRelation}};
use mdd_types::{DecimalU64,MddResult};
use std::sync::Arc;

struct Provider { binding: SqlBinding }
impl SqlFactProvider for Provider {
    fn binding(&self) -> &SqlBinding { &self.binding }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> { Ok(vec![]) }
    fn require_relation(&self, _: &str) -> MddResult<()> { unreachable!() }
    fn open_cursor(self: Arc<Self>, _: &str, _: SqlControl) -> MddResult<Box<dyn SqlFactCursor>> { unreachable!() }
}

fn main() {
    let cases = [
        ("positive", "SELECT substr('abcdef',2,3) AS value"),
        ("negative_start", "SELECT substr('abcdef',-3,2) AS value"),
        ("negative_length", "SELECT substr('abcdef',4,-2) AS value"),
        ("nul", "SELECT substr('A\0B',2,2) AS value"),
        ("supplementary", "SELECT substr('😀A',1,1) AS value"),
        ("null", "SELECT substr(NULL,1,1) AS value"),
        ("bytes", "SELECT substr(X'414243',2,1) AS value"),
        ("substring", "SELECT substring('abcdef',2,3) AS value"),
    ];
    let mut output = Vec::new();
    for (name,dialect) in [("A0",SqlDialect::DexSql010),("A1",SqlDialect::DexSql011)] {
        let provider=Arc::new(Provider{binding:SqlBinding{provider_identity:"literal-only-probe".into(),snapshot_id:"synthetic".into(),catalog_epoch:DecimalU64(0)}});
        let bridge=SqlBridge::new(provider,dialect,SqlLimits::default()).unwrap();
        for (id,sql) in cases {
            let value=match bridge.query(sql) { Ok(v)=>serde_json::json!({"status":"ok","result":v}), Err(e)=>serde_json::json!({"status":"error","error":e}) };
            output.push(serde_json::json!({"dialect":name,"case":id,"output":value}));
        }
    }
    println!("{}",serde_json::to_string(&output).unwrap());
}
