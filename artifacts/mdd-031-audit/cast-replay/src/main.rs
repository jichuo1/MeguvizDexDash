use mdd_dex::{annotations::AnnotationLimits,definitions::DefinitionLimits,strings::StringLimits};
use mdd_facts::{MetadataFacts,definitions::DefinitionFacts,annotations::AnnotationFacts};
use mdd_input::{archive::{ArchiveInventory,ArchiveLimits,InventoryPolicy},snapshot::{Snapshot,CaptureLimits,InputKind,InputSpec}};
use mdd_sql::{SqlBridge,control::{SqlControl,SqlLimits},dialects::SqlDialect,provider::{SqlBinding,SqlColumn,SqlFactCursor,SqlFactProvider,SqlRelation,metadata::MetadataSqlProvider},values::SqlType};
use mdd_types::{DecimalU64,MddResult};use std::{path::PathBuf,sync::Arc};

fn input(rel:&str,sha:&str)->(Arc<Snapshot>,Arc<ArchiveInventory>){
 let path=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").join(rel);
 let s=Arc::new(Snapshot::capture(&[InputSpec{path,kind:InputKind::RawDex,expected_sha256:Some(sha.into())}],CaptureLimits::default()).unwrap());
 let a=Arc::new(ArchiveInventory::build(&s.sources()[0],InventoryPolicy::default(),ArchiveLimits::default()).unwrap());(s,a)
}
fn bridge(s:&Snapshot,a:&ArchiveInventory,d:SqlDialect,limits:SqlLimits)->SqlBridge{
 let facts=Arc::new(MetadataFacts::build(s,a,0,StringLimits::default()).unwrap());
 SqlBridge::new(Arc::new(MetadataSqlProvider::new(vec![facts],DecimalU64(0)).unwrap()),d,limits).unwrap()
}
fn outcome(r:MddResult<mdd_sql::SqlResult>)->serde_json::Value{match r{Ok(v)=>serde_json::json!({"status":"ok","result":v}),Err(e)=>serde_json::json!({"status":"error","error":e})}}
fn annotations(s:&Snapshot,a:&ArchiveInventory)->MddResult<AnnotationFacts>{let m=MetadataFacts::build(s,a,0,StringLimits::default())?;let d=DefinitionFacts::build(m,DefinitionLimits::default())?;AnnotationFacts::build(d,AnnotationLimits::default())}
struct BadProvider{binding:SqlBinding,s:Arc<Snapshot>,a:Arc<ArchiveInventory>}
impl SqlFactProvider for BadProvider{
 fn binding(&self)->&SqlBinding{&self.binding}
 fn relations(&self)->MddResult<Vec<SqlRelation>>{Ok(vec![SqlRelation{name:"annotation_elements".into(),columns:vec![SqlColumn{id:"value_index".into(),name:"value_index".into(),data_type:SqlType::U64,nullable:true}],required_layers:vec![],estimated_rows:None}])}
 fn require_relation(&self,_:&str)->MddResult<()>{annotations(&self.s,&self.a).map(|_|())}
 fn open_cursor(self:Arc<Self>,_:&str,_:SqlControl)->MddResult<Box<dyn SqlFactCursor>>{unreachable!("LIMIT 0 should not open cursor")}
}
fn main(){
 let classic=input("tests/fixtures/references/generated/classic-035.dex","076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8");
 let dex=input("tests/fixtures/generated/strings-mutf8-035.dex","4deab5f75b23c118b170005d89a6ebc0d18d894383280253e70de0507d260f35");
 let cases:serde_json::Value=serde_json::from_str(include_str!("../cases.json")).unwrap();let mut output=vec![];
 for (name,dialect) in [("A0",SqlDialect::DexSql010),("A1",SqlDialect::DexSql011)]{
  for kind in ["literals","dex"]{let (s,a)=if kind=="literals"{&classic}else{&dex};let b=bridge(s,a,dialect,SqlLimits::default());
   for c in cases[kind].as_array().unwrap(){let sql=c["sql"].as_str().unwrap();let candidate_sql=if kind=="dex"{sql.replace("FROM strings","FROM native_strings")}else{sql.to_owned()};output.push(serde_json::json!({"engine":name,"kind":kind,"id":c["id"],"reference_sql":sql,"candidate_sql":candidate_sql,"output":outcome(b.query(&candidate_sql))}));}
  }
  let sql=format!("SELECT CAST('{}' AS INTEGER) AS v","9".repeat(4096));
  let limits=SqlLimits{max_cell_bytes:128,..SqlLimits::default()};let b=bridge(&classic.0,&classic.1,dialect,limits);
  output.push(serde_json::json!({"engine":name,"kind":"budget","id":"long_cell","output":outcome(b.query(&sql))}));
  let limits=SqlLimits{max_steps:1,..SqlLimits::default()};let b=bridge(&classic.0,&classic.1,dialect,limits);
  output.push(serde_json::json!({"engine":name,"kind":"budget","id":"steps","output":outcome(b.query(&sql))}));
  let b=bridge(&classic.0,&classic.1,dialect,SqlLimits::default());let q=b.prepare("SELECT CAST('12' AS INTEGER)").unwrap();let c=SqlControl::new(SqlLimits::default(),None);c.cancel().unwrap();
  output.push(serde_json::json!({"engine":name,"kind":"budget","id":"cancel","output":outcome(q.execute(c))}));
 }
 let (s,a)=input("tests/fixtures/annotations/generated/bad-string-index.dex","99b52e4d7de2655419dc3c7db73baafc5ba24bcc2832f0a8d2b2ffc2d04720c5");
 let direct=annotations(&s,&a).err().expect("bad fixture must fail");
 let bad=Arc::new(BadProvider{binding:SqlBinding{provider_identity:"actual-corrupt-dex".into(),snapshot_id:"fixture-only".into(),catalog_epoch:DecimalU64(0)},s,a});
 let b=SqlBridge::new(bad,SqlDialect::DexSql010,SqlLimits::default()).unwrap();
 let corrupt=outcome(b.query("SELECT value_index FROM annotation_elements LIMIT 0"));
 println!("{}",serde_json::json!({"cases":output,"actual_corrupt_dex":{"direct":direct,"bridge":corrupt},"profiles_admitted":false}));
}
