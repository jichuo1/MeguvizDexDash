use mdd_sql::{SqlBridge, control::{SqlControl,SqlLimits}, dialects::SqlDialect,
    provider::{SqlBinding,SqlColumn,SqlFactCursor,SqlFactProvider,SqlRelation,SqlRow},
    values::{SqlType,SqlValue}};
use mdd_types::{DecimalU64,ErrorCode,MddError,MddResult};
use serde_json::{Value,json};
use std::{path::PathBuf,sync::Arc};

struct Provider(SqlBinding); struct Cursor(std::vec::IntoIter<SqlRow>);
fn signed(v:i64)->SqlValue {serde_json::from_value(json!({"type":"i64","value":v.to_string()})).unwrap()}
impl SqlFactCursor for Cursor {fn next_row(&mut self)->MddResult<Option<SqlRow>>{Ok(self.0.next())}}
fn column(name:&str,t:SqlType,nullable:bool)->SqlColumn{
    SqlColumn{id:name.into(),name:name.into(),data_type:t,nullable}
}
impl SqlFactProvider for Provider{
    fn binding(&self)->&SqlBinding{&self.0}
    fn relations(&self)->MddResult<Vec<SqlRelation>>{
        Ok(vec![SqlRelation{name:"facts".into(),columns:vec![column("id",SqlType::I64,false),
            column("c",SqlType::Text,false),column("d",SqlType::Text,false),column("v",SqlType::I64,true)],
            required_layers:vec![],estimated_rows:Some(DecimalU64(3))}])
    }
    fn require_relation(&self,name:&str)->MddResult<()>{
        if name=="facts"{Ok(())}else{Err(MddError::new(ErrorCode::InvalidArgument,"fixture","unknown relation"))}
    }
    fn open_cursor(self:Arc<Self>,name:&str,_:SqlControl)->MddResult<Box<dyn SqlFactCursor>>{
        self.require_relation(name)?;
        let rows=vec![vec![signed(1),SqlValue::text("a"),SqlValue::text("B"),signed(2)],
                      vec![signed(2),SqlValue::text("a"),SqlValue::text("B"),SqlValue::Null],
                      vec![signed(3),SqlValue::text("z"),SqlValue::text("A"),signed(1)]];
        Ok(Box::new(Cursor(rows.into_iter())))
    }
}
fn main(){
    let reference:Value=serde_json::from_slice(&std::fs::read(PathBuf::from(
        "artifacts/mdd-031-audit/multi-minmax-independent-20261029/sqlite-reference.json")).unwrap()).unwrap();
    let mut records=Vec::new();
    for (name,dialect) in [("native",SqlDialect::NativeV1),("010",SqlDialect::DexSql010),("011",SqlDialect::DexSql011)]{
        let provider=Arc::new(Provider(SqlBinding{provider_identity:"synthetic-minmax".into(),
            snapshot_id:"fixture-only".into(),catalog_epoch:DecimalU64(0)}));
        let bridge=SqlBridge::new(provider,dialect,SqlLimits::default()).unwrap();
        for case in reference["records"].as_array().unwrap(){
            let id=case["case"].as_str().unwrap();let sql=case["sql"].as_str().unwrap();
            let result=match bridge.query(sql){Ok(v)=>json!({"status":"ok","result":v}),
                Err(error)=>json!({"status":"error","error":error})};
            records.push(json!({"dialect":name,"case":id,"sql":sql,"result":result}));
        }
    }
    println!("{}",json!({"records":records,"profile_admitted":false,
        "scope":"synthetic SQL provider; no declared per-column collation; no old-engine or transport qualification"}));
}
