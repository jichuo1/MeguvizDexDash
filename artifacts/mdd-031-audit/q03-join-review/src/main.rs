use mdd_sql::{SqlBridge,control::{SqlControl,SqlLimits},dialects::SqlDialect,provider::{SqlBinding,SqlColumn,SqlFactCursor,SqlFactProvider,SqlRelation,SqlRow},values::{SqlType,SqlValue}};
use mdd_types::{DecimalU64,ErrorCode,MddError,MddResult};use std::sync::Arc;
struct P(SqlBinding);struct C(std::vec::IntoIter<SqlRow>);
impl SqlFactCursor for C{fn next_row(&mut self)->MddResult<Option<SqlRow>>{Ok(self.0.next())}}
fn col(n:&str,t:SqlType)->SqlColumn{SqlColumn{id:n.into(),name:n.into(),data_type:t,nullable:false}}
impl SqlFactProvider for P{
 fn binding(&self)->&SqlBinding{&self.0}
 fn relations(&self)->MddResult<Vec<SqlRelation>>{Ok(vec![
  SqlRelation{name:"classes".into(),columns:vec![col("file_id",SqlType::U64),col("class_idx",SqlType::U64),col("descriptor",SqlType::Text)],required_layers:vec![],estimated_rows:Some(DecimalU64(2))},
  SqlRelation{name:"class_interfaces".into(),columns:vec![col("file_id",SqlType::U64),col("class_idx",SqlType::U64),col("ordinal",SqlType::U64),col("interface_descriptor",SqlType::Text),col("descriptor",SqlType::U64)],required_layers:vec![],estimated_rows:Some(DecimalU64(4))}])}
 fn require_relation(&self,n:&str)->MddResult<()>{if ["classes","class_interfaces"].contains(&n){Ok(())}else{Err(MddError::new(ErrorCode::InvalidArgument,"fixture","unknown relation"))}}
 fn open_cursor(self:Arc<Self>,n:&str,_:SqlControl)->MddResult<Box<dyn SqlFactCursor>>{
  self.require_relation(n)?;let data:serde_json::Value=serde_json::from_str(include_str!("../fixture.json")).unwrap();
  let rows=data[n].as_array().unwrap().iter().map(|row|row.as_array().unwrap().iter().map(|value|if let Some(s)=value.as_str(){SqlValue::text(s)}else{SqlValue::U64(DecimalU64(value.as_u64().unwrap()))}).collect()).collect::<Vec<_>>();Ok(Box::new(C(rows.into_iter())))
 }
}
fn main(){
 let q03="SELECT ci.interface_descriptor,c.descriptor FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE c.descriptor IN ('Lfixture/A;') ORDER BY ci.file_id,ci.class_idx,ci.ordinal";
 let cases=[
  ("q03",q03),
  ("numeric_alias","SELECT ci.ordinal FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE ci.descriptor IN (1) ORDER BY ci.ordinal"),
  ("mixed_alias","SELECT ci.ordinal FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE ci.descriptor IN ('1')"),
  ("ambiguous","SELECT descriptor IN ('1') FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx"),
  ("unknown_alias","SELECT z.descriptor IN ('1') FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx"),
  ("duplicate_alias","SELECT c.descriptor IN ('1') FROM classes c JOIN class_interfaces c ON 1=1"),
  ("multi_from","SELECT ci.interface_descriptor,c.descriptor FROM class_interfaces ci,classes c WHERE c.file_id=ci.file_id AND c.class_idx=ci.class_idx AND c.descriptor IN ('Lfixture/A;') ORDER BY ci.file_id,ci.class_idx,ci.ordinal"),
  ("derived_shadow","SELECT d.descriptor IN (1) AS v FROM (SELECT CAST('1' AS TEXT) AS descriptor) d"),
  ("cte_shadow","WITH d AS (SELECT CAST('1' AS TEXT) AS descriptor) SELECT d.descriptor IN (1) AS v FROM d"),
  ("correlated_local","SELECT c.descriptor FROM classes c WHERE EXISTS (SELECT 1 FROM class_interfaces ci WHERE ci.descriptor IN (1) AND ci.file_id=c.file_id AND ci.class_idx=c.class_idx) ORDER BY c.descriptor"),
  ("correlated_outer","SELECT c.descriptor FROM classes c WHERE EXISTS (SELECT 1 FROM class_interfaces ci WHERE c.descriptor IN ('Lfixture/A;') AND ci.file_id=c.file_id AND ci.class_idx=c.class_idx) ORDER BY c.descriptor"),
 ];
 let mut out=vec![];
 for (name,dialect) in [("010",SqlDialect::DexSql010),("011",SqlDialect::DexSql011)]{
  let p=Arc::new(P(SqlBinding{provider_identity:"synthetic-q03".into(),snapshot_id:"fixture-only".into(),catalog_epoch:DecimalU64(0)}));let bridge=SqlBridge::new(p,dialect,SqlLimits::default()).unwrap();
  for (id,sql) in cases{let result=match bridge.query(sql){Ok(x)=>serde_json::json!({"status":"ok","value":x}),Err(e)=>serde_json::json!({"status":"error","error":e})};out.push(serde_json::json!({"dialect":name,"case":id,"sql":sql,"result":result}));}
 }
 println!("{}",serde_json::to_string(&out).unwrap());
}
