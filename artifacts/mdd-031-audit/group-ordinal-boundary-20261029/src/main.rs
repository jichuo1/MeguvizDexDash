use mdd_sql::{SqlBridge, control::{SqlControl,SqlLimits}, dialects::SqlDialect,
    provider::{SqlBinding,SqlColumn,SqlFactCursor,SqlFactProvider,SqlRelation,SqlRow},
    values::{SqlType,SqlValue}};
use mdd_types::{DecimalU64,ErrorCode,MddError,MddResult};
use serde_json::{Value,json};
use std::sync::Arc;

struct Provider { binding:SqlBinding, mode:&'static str }
struct Cursor { rows:std::vec::IntoIter<SqlRow>, fail_after_first:bool, emitted:usize }
fn signed(value:i64)->SqlValue { serde_json::from_value(json!({"type":"i64","value":value.to_string()})).unwrap() }
impl SqlFactCursor for Cursor {
    fn next_row(&mut self)->MddResult<Option<SqlRow>> {
        if self.fail_after_first && self.emitted==1 {
            return Err(MddError::new(ErrorCode::SourceChanged,"fixture.source","injected source changed"));
        }
        let row=self.rows.next(); if row.is_some() { self.emitted+=1; } Ok(row)
    }
}
impl SqlFactProvider for Provider {
    fn binding(&self)->&SqlBinding { &self.binding }
    fn relations(&self)->MddResult<Vec<SqlRelation>> {
        Ok(vec![SqlRelation{name:"facts".into(),columns:vec![
            SqlColumn{id:"k".into(),name:"k".into(),data_type:SqlType::I64,nullable:true},
            SqlColumn{id:"alt".into(),name:"alt".into(),data_type:SqlType::I64,nullable:false}],
            required_layers:vec![],estimated_rows:Some(DecimalU64(4))}])
    }
    fn require_relation(&self,name:&str)->MddResult<()> {
        if name!="facts" { return Err(MddError::new(ErrorCode::InvalidArgument,"fixture","unknown relation")); }
        if self.mode=="missing" { return Err(MddError::new(ErrorCode::IncompleteFacts,"fixture.coverage","required facts incomplete")); }
        Ok(())
    }
    fn open_cursor(self:Arc<Self>,name:&str,_:SqlControl)->MddResult<Box<dyn SqlFactCursor>> {
        self.require_relation(name)?;
        let values=vec![vec![SqlValue::Null,signed(9)],vec![signed(1),signed(10)],
                        vec![signed(1),signed(20)],vec![signed(2),signed(30)]];
        Ok(Box::new(Cursor{rows:values.into_iter(),fail_after_first:self.mode=="source_changed",emitted:0}))
    }
}

fn run(dialect:SqlDialect,sql:&str,mode:&'static str,steps:u64,cancel:bool)->Value {
    let limits=SqlLimits{max_steps:steps,..SqlLimits::default()};
    let provider=Arc::new(Provider{binding:SqlBinding{provider_identity:"group-ordinal-fixture".into(),
        snapshot_id:"fixture-only".into(),catalog_epoch:DecimalU64(0)},mode});
    let bridge=SqlBridge::new(provider,dialect,limits).unwrap();
    let prepared=match bridge.prepare(sql){Ok(v)=>v,Err(error)=>return json!({"status":"prepare_error","error":error})};
    let control=SqlControl::new(limits,None); if cancel {control.cancel().unwrap();}
    match bridge.execute(&prepared,control){Ok(v)=>json!({"status":"ok","result":v}),Err(error)=>json!({"status":"error","error":error})}
}
fn main(){
    let cases=[
        ("plain","SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY 1 ORDER BY g","values",100000,false),
        ("parenthesized","SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY (1) ORDER BY g","values",100000,false),
        ("nested","SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY (((1))) ORDER BY g","values",100000,false),
        ("expression_constant","SELECT COUNT(*) AS n FROM facts GROUP BY (1+0)","values",100000,false),
        ("two_positions","SELECT k+1 AS g,alt AS h,COUNT(*) AS n FROM facts GROUP BY (1),(2) ORDER BY g,h","values",100000,false),
        ("alias","SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY g ORDER BY g","values",100000,false),
        ("alias_having","SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY g HAVING COUNT(*)>1 ORDER BY g","values",100000,false),
        ("ordinal_having","SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY (1) HAVING COUNT(*)>1 ORDER BY g","values",100000,false),
        ("alias_input_collision","SELECT k+1 AS alt,COUNT(*) AS n FROM facts GROUP BY alt ORDER BY alt","values",100000,false),
        ("empty","SELECT k+1 AS g,COUNT(*) AS n FROM facts WHERE 0 GROUP BY (1) ORDER BY g","values",100000,false),
        ("zero","SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY (0)","values",100000,false),
        ("range","SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY (3)","values",100000,false),
        ("aggregate_position","SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY (2)","values",100000,false),
        ("unknown","SELECT k+1 AS g,COUNT(*) AS n FROM facts GROUP BY absent","values",100000,false),
        ("order_max","SELECT k FROM facts WHERE k IS NOT NULL ORDER BY 2147483647","values",100000,false),
        ("order_above","SELECT k FROM facts WHERE k IS NOT NULL ORDER BY 2147483648","values",100000,false),
        ("order_negmax","SELECT k FROM facts WHERE k IS NOT NULL ORDER BY -2147483647","values",100000,false),
        ("order_negmin","SELECT k FROM facts WHERE k IS NOT NULL ORDER BY -2147483648","values",100000,false),
        ("order_posabove","SELECT k FROM facts WHERE k IS NOT NULL ORDER BY +2147483648","values",100000,false),
        ("order_real","SELECT k FROM facts WHERE k IS NOT NULL ORDER BY 1.0","values",100000,false),
        ("group_max","SELECT COUNT(*) AS n FROM facts WHERE k IS NOT NULL GROUP BY 2147483647","values",100000,false),
        ("group_above","SELECT COUNT(*) AS n FROM facts WHERE k IS NOT NULL GROUP BY 2147483648","values",100000,false),
        ("group_negmax","SELECT COUNT(*) AS n FROM facts WHERE k IS NOT NULL GROUP BY -2147483647","values",100000,false),
        ("group_negmin","SELECT COUNT(*) AS n FROM facts WHERE k IS NOT NULL GROUP BY -2147483648","values",100000,false),
        ("group_posabove","SELECT COUNT(*) AS n FROM facts WHERE k IS NOT NULL GROUP BY +2147483648","values",100000,false),
        ("group_real","SELECT COUNT(*) AS n FROM facts WHERE k IS NOT NULL GROUP BY 1.0","values",100000,false),
        ("missing_limit_zero","SELECT k,COUNT(*) FROM facts GROUP BY (1) LIMIT 0","missing",100000,false),
        ("source_changed","SELECT k,COUNT(*) FROM facts GROUP BY (1)","source_changed",100000,false),
        ("step_limit","SELECT k,COUNT(*) FROM facts GROUP BY (1)","values",1,false),
        ("cancelled","SELECT k,COUNT(*) FROM facts GROUP BY (1)","values",100000,true),
    ];
    let mut records=Vec::new();
    for (name,dialect) in [("native",SqlDialect::NativeV1),("010",SqlDialect::DexSql010),("011",SqlDialect::DexSql011)]{
        for (id,sql,mode,steps,cancel) in cases { records.push(json!({"dialect":name,"case":id,"sql":sql,"result":run(dialect,sql,mode,steps,cancel)})); }
    }
    println!("{}",json!({"records":records,"profile_admitted":false,
        "scope":"synthetic provider, SQL grouping; injected errors; no full facts or transport qualification"}));
}
