use mdd_sql::{SqlBridge,control::{SqlControl,SqlLimits},dialects::SqlDialect,provider::{SqlBinding,SqlColumn,SqlFactCursor,SqlFactProvider,SqlRelation,SqlRow},values::{SqlText,SqlType,SqlValue}};
use mdd_types::{DecimalU64,MddResult};
use std::sync::Arc;

const SQL:&str="SELECT CASE WHEN \"val\" IS NULL THEN 'N' ELSE hex(CAST(\"val\" AS TEXT)) END AS \"val\" FROM (SELECT id,val FROM sample ORDER BY id) AS hostlab_rows";
struct Provider{binding:SqlBinding,long:bool}
struct Cursor{rows:std::vec::IntoIter<SqlRow>}
impl SqlFactCursor for Cursor{fn next_row(&mut self)->MddResult<Option<SqlRow>>{Ok(self.rows.next())}}
impl SqlFactProvider for Provider{
 fn binding(&self)->&SqlBinding{&self.binding}
 fn relations(&self)->MddResult<Vec<SqlRelation>>{
  Ok(vec![SqlRelation{name:"sample".into(),columns:vec![
   SqlColumn{id:"id".into(),name:"id".into(),data_type:SqlType::U64,nullable:false},
   SqlColumn{id:"val".into(),name:"val".into(),data_type:SqlType::Text,nullable:true}],
   required_layers:vec![],estimated_rows:Some(DecimalU64(7))}])
 }
 fn require_relation(&self,_:&str)->MddResult<()>{Ok(())}
 fn open_cursor(self:Arc<Self>,_:&str,_:SqlControl)->MddResult<Box<dyn SqlFactCursor>>{
  let text=|v:Vec<u16>|SqlValue::Text(SqlText{utf16:v,original_mutf8:None});
  let values=if self.long {vec![SqlValue::text(&"Z".repeat(50_000))]} else {vec![SqlValue::Null,SqlValue::text(""),SqlValue::text("alpha"),text(vec![65,0,66]),text(vec![0xd83d,0xde00]),SqlValue::text("N"),text(vec![0xd800])]};
  let rows=values.into_iter().enumerate().map(|(i,v)|vec![SqlValue::U64(DecimalU64(i as u64)),v]).collect::<Vec<_>>();
  Ok(Box::new(Cursor{rows:rows.into_iter()}))
 }
}
fn main(){let mut all=Vec::new();for dialect in [SqlDialect::NativeV1,SqlDialect::DexSql010,SqlDialect::DexSql011]{
 let p=Arc::new(Provider{binding:SqlBinding{provider_identity:"case-hex-synthetic".into(),snapshot_id:"synthetic-snapshot".into(),catalog_epoch:DecimalU64(0)},long:false});
 let bridge=SqlBridge::new(p,dialect,SqlLimits::default()).unwrap();
 for(name,sql) in [("shape","SELECT * FROM (SELECT id,val FROM sample ORDER BY id) AS hostlab_shape LIMIT 0"),("wrapped",SQL)]{
  let result=match bridge.query(sql){Ok(v)=>serde_json::json!({"status":"ok","result":v}),Err(e)=>serde_json::json!({"status":"error","error":e})};
  all.push(serde_json::json!({"dialect":format!("{dialect:?}"),"case":name,"sql":sql,"output":result}));
 }
 for(name,sql) in [("distinct_quota","SELECT DISTINCT val FROM sample"),("group_quota","SELECT val,COUNT(*) FROM sample GROUP BY val"),("order_quota","SELECT val FROM sample ORDER BY val")]{
  let p=Arc::new(Provider{binding:SqlBinding{provider_identity:"key-synthetic".into(),snapshot_id:"synthetic-snapshot".into(),catalog_epoch:DecimalU64(0)},long:true});
  let b=SqlBridge::new(p,dialect,SqlLimits::default()).unwrap();
  let limits=SqlLimits{max_steps:64,..SqlLimits::default()};
  let result=match b.prepare(sql).and_then(|p|p.execute(SqlControl::new(limits,None))){Ok(v)=>serde_json::json!({"status":"ok","result":v}),Err(e)=>serde_json::json!({"status":"error","error":e})};
  all.push(serde_json::json!({"dialect":format!("{dialect:?}"),"case":name,"sql":sql,"output":result}));
 }
}println!("{}",serde_json::json!({"records":all,"profiles_admitted":false,"scope":"synthetic provider and literal HostLab wrapper shape"}));}
