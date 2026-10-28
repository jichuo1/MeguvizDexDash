use mdd_sql::{SqlBridge,control::{SqlControl,SqlLimits},dialects::SqlDialect,provider::{SqlBinding,SqlFactCursor,SqlFactProvider,SqlRelation}};
use mdd_types::{DecimalU64,MddResult};
use std::sync::Arc;
struct Provider(SqlBinding);
impl SqlFactProvider for Provider{
 fn binding(&self)->&SqlBinding{&self.0}
 fn relations(&self)->MddResult<Vec<SqlRelation>>{Ok(vec![])}
 fn require_relation(&self,_:&str)->MddResult<()>{unreachable!()}
 fn open_cursor(self:Arc<Self>,_:&str,_:SqlControl)->MddResult<Box<dyn SqlFactCursor>>{unreachable!()}
}
fn main(){
 let p=Arc::new(Provider(SqlBinding{provider_identity:"cancel-synthetic".into(),snapshot_id:"synthetic".into(),catalog_epoch:DecimalU64(0)}));
 let bridge=SqlBridge::new(p,SqlDialect::DexSql010,SqlLimits::default()).unwrap();
 let query=bridge.prepare("SELECT 1 IN (1)").unwrap();
 let control=SqlControl::new(SqlLimits::default(),None);
 control.cancel().unwrap();
 let output=match query.execute(control){Ok(r)=>serde_json::json!({"status":"ok","result":r}),Err(e)=>serde_json::json!({"status":"error","error":e})};
 println!("{output}");
}
