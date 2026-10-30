use mdd_sql::{SqlBridge,control::{SqlControl,SqlLimits},dialects::SqlDialect,provider::{SqlBinding,SqlColumn,SqlFactCursor,SqlFactProvider,SqlRelation,SqlRow},values::{SqlType,SqlValue}};
use mdd_types::{DecimalU64,ErrorCode,MddError,MddResult};
use std::sync::{Arc,atomic::{AtomicUsize,Ordering}};

const SQL:&str="SELECT file_id,method,callee,COUNT(*) AS n FROM method_calls WHERE file_id=0 AND (callee_class LIKE 'Lfixture/%' ESCAPE '\\') GROUP BY file_id,method,callee ORDER BY file_id,method,callee";
struct Provider{binding:SqlBinding,mode:&'static str,requires:AtomicUsize,opens:AtomicUsize}
struct Cursor{rows:std::vec::IntoIter<SqlRow>,mode:&'static str,position:usize}
impl SqlFactCursor for Cursor {
 fn next_row(&mut self)->MddResult<Option<SqlRow>>{
  if self.mode=="source_changed" && self.position==1 {return Err(MddError::new(ErrorCode::SourceChanged,"fixture.cursor","synthetic source mutation"));}
  let row=self.rows.next(); self.position+=usize::from(row.is_some()); Ok(row)
 }
}
impl SqlFactProvider for Provider{
 fn binding(&self)->&SqlBinding{&self.binding}
 fn relations(&self)->MddResult<Vec<SqlRelation>>{
  let names=["method","method_class","method_name","callee","callee_class","callee_name","file_id","class_idx","method_idx","callee_method_idx"];
  Ok(vec![SqlRelation{name:"method_calls".into(),columns:names.iter().enumerate().map(|(i,n)|SqlColumn{id:(*n).into(),name:(*n).into(),data_type:if i<6{SqlType::Text}else{SqlType::U64},nullable:false}).collect(),required_layers:vec![],estimated_rows:Some(DecimalU64(6))}])
 }
 fn require_relation(&self,_:&str)->MddResult<()>{self.requires.fetch_add(1,Ordering::SeqCst); if self.mode=="missing"{Err(MddError::new(ErrorCode::IncompleteFacts,"fixture.coverage","required fact layer missing"))}else{Ok(())}}
 fn open_cursor(self:Arc<Self>,_:&str,_:SqlControl)->MddResult<Box<dyn SqlFactCursor>>{
  self.opens.fetch_add(1,Ordering::SeqCst);
  let json:Vec<Vec<serde_json::Value>>=serde_json::from_str(include_str!("../fixture.json")).unwrap();
  let rows=json.into_iter().map(|row|row.into_iter().enumerate().map(|(i,v)|if i<6{SqlValue::text(v.as_str().unwrap())}else{SqlValue::U64(DecimalU64(v.as_u64().unwrap()))}).collect()).collect::<Vec<_>>();
  Ok(Box::new(Cursor{rows:rows.into_iter(),mode:self.mode,position:0}))
 }
}
fn main(){
 let mut output=Vec::new();
 for (mode,sql) in [("normal",SQL),("empty","SELECT file_id,method,callee,COUNT(*) AS n FROM method_calls WHERE file_id=999 GROUP BY file_id,method,callee ORDER BY file_id,method,callee"),("missing","SELECT * FROM method_calls LIMIT 0"),("source_changed",SQL)]{
  let p=Arc::new(Provider{binding:SqlBinding{provider_identity:"q10-synthetic".into(),snapshot_id:"synthetic-only".into(),catalog_epoch:DecimalU64(0)},mode,requires:AtomicUsize::new(0),opens:AtomicUsize::new(0)});
  let bridge=SqlBridge::new(p.clone(),SqlDialect::DexSql010,SqlLimits::default()).unwrap();
  let result=match bridge.query(sql){Ok(v)=>serde_json::json!({"status":"ok","result":v}),Err(e)=>serde_json::json!({"status":"error","error":e})};
  output.push(serde_json::json!({"mode":mode,"sql":sql,"result":result,"requires":p.requires.load(Ordering::SeqCst),"opens":p.opens.load(Ordering::SeqCst)}));
 }
 println!("{}",serde_json::to_string(&output).unwrap());
}
