use mdd_sql::{SqlBridge, control::{SqlControl,SqlLimits}, dialects::SqlDialect,
    provider::{SqlBinding,SqlColumn,SqlFactCursor,SqlFactProvider,SqlRelation,SqlRow},
    values::{SqlType,SqlValue}};
use mdd_types::{DecimalU64,ErrorCode,MddError,MddResult};
use serde_json::{Value,json};
use std::sync::Arc;

struct Provider { binding: SqlBinding, mode: &'static str }
struct Cursor { rows: std::vec::IntoIter<SqlRow>, fail_after_first: bool, emitted: usize }
fn signed(value: i64) -> SqlValue {
    serde_json::from_value(json!({"type":"i64","value":value.to_string()})).unwrap()
}
impl SqlFactCursor for Cursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        if self.fail_after_first && self.emitted == 1 {
            return Err(MddError::new(ErrorCode::SourceChanged,"fixture.source","injected source changed"));
        }
        let row=self.rows.next();
        if row.is_some() { self.emitted+=1; }
        Ok(row)
    }
}
impl SqlFactProvider for Provider {
    fn binding(&self) -> &SqlBinding { &self.binding }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        Ok(vec![SqlRelation{name:"facts".into(),columns:vec![SqlColumn{id:"v".into(),name:"v".into(),
            data_type:SqlType::I64,nullable:true},SqlColumn{id:"alt".into(),name:"alt".into(),
            data_type:SqlType::I64,nullable:false}],required_layers:vec![],estimated_rows:Some(DecimalU64(4))}])
    }
    fn require_relation(&self,name:&str) -> MddResult<()> {
        if name!="facts" { return Err(MddError::new(ErrorCode::InvalidArgument,"fixture","unknown relation")); }
        if self.mode=="missing" { return Err(MddError::new(ErrorCode::IncompleteFacts,"fixture.coverage","required facts incomplete")); }
        Ok(())
    }
    fn open_cursor(self:Arc<Self>,name:&str,_:SqlControl) -> MddResult<Box<dyn SqlFactCursor>> {
        self.require_relation(name)?;
        let values=if self.mode=="empty" { vec![] } else {
            vec![vec![SqlValue::Null,signed(7)],vec![signed(2),signed(3)],
                 vec![signed(2),signed(-9)],vec![signed(-1),signed(2)]]
        };
        Ok(Box::new(Cursor { rows:values.into_iter(),fail_after_first:self.mode=="source_changed",emitted:0 }))
    }
}

fn run(dialect:SqlDialect, sql:&str, mode:&'static str, rows:u64, steps:u64, cancel:bool) -> Value {
    let limits=SqlLimits{max_result_rows:rows,max_steps:steps,..SqlLimits::default()};
    let provider=Arc::new(Provider{binding:SqlBinding{provider_identity:"synthetic-null-aggregate".into(),
        snapshot_id:"fixture-only".into(),catalog_epoch:DecimalU64(0)},mode});
    let bridge=SqlBridge::new(provider,dialect,limits).unwrap();
    let prepared=match bridge.prepare(sql) { Ok(v)=>v,Err(error)=>return json!({"status":"prepare_error","error":error}) };
    let control=SqlControl::new(limits,None);
    if cancel { control.cancel().unwrap(); }
    match bridge.execute(&prepared,control) {
        Ok(v)=>json!({"status":"ok","result":v}),Err(error)=>json!({"status":"error","error":error})
    }
}
fn main() {
    let cases=[
        ("a0_null_order","SELECT 0 AS v UNION ALL SELECT NULL AS v ORDER BY v","values",100,100000,false),
        ("ascending","SELECT v FROM facts ORDER BY v ASC","values",100,100000,false),
        ("descending","SELECT v FROM facts ORDER BY v DESC","values",100,100000,false),
        ("distinct","SELECT DISTINCT v FROM facts ORDER BY v","values",100,100000,false),
        ("groups","SELECT v,COUNT(*) AS n FROM facts GROUP BY v ORDER BY v","values",100,100000,false),
        ("aggregate","SELECT COUNT(*) AS n,COUNT(v) AS nonnull,COUNT(DISTINCT v) AS distinct_n,MIN(v) AS lo,MAX(v) AS hi,SUM(v) AS total FROM facts","values",100,100000,false),
        ("empty_aggregate","SELECT COUNT(*) AS n,COUNT(v) AS nonnull,MIN(v) AS lo,MAX(v) AS hi,SUM(v) AS total FROM facts","empty",100,100000,false),
        ("shadow_input","SELECT v AS alt FROM facts ORDER BY alt","values",100,100000,false),
        ("expression_shadow","SELECT -v AS v FROM facts ORDER BY v","values",100,100000,false),
        ("duplicate_alias","SELECT alt AS z,v AS z FROM facts ORDER BY z","values",100,100000,false),
        ("multiple_keys","SELECT v AS value,alt FROM facts ORDER BY value,alt DESC","values",100,100000,false),
        ("wildcard_order","SELECT * FROM facts ORDER BY v DESC,alt ASC","values",100,100000,false),
        ("positional","SELECT * FROM facts ORDER BY 1,2 DESC","values",100,100000,false),
        ("parenthesized_ordinal","SELECT v,alt FROM facts ORDER BY (1),(2) DESC","values",100,100000,false),
        ("limit_order","SELECT v AS alt FROM facts ORDER BY alt LIMIT 2","values",100,100000,false),
        ("cte_alias","WITH s AS (SELECT v,alt FROM facts) SELECT v AS alt FROM s ORDER BY alt","values",100,100000,false),
        ("compound_null","SELECT 2 AS val UNION ALL SELECT NULL AS val UNION ALL SELECT -1 AS val ORDER BY val","values",100,100000,false),
        ("unknown_order","SELECT v FROM facts ORDER BY missing","values",100,100000,false),
        ("ordinal_out_of_range","SELECT v FROM facts ORDER BY 3","values",100,100000,false),
        ("result_limit","SELECT v FROM facts","values",1,100000,false),
        ("step_limit","SELECT COUNT(*) AS n FROM facts","values",100,1,false),
        ("cancelled","SELECT COUNT(*) AS n FROM facts","values",100,100000,true),
        ("missing_limit_zero","SELECT v FROM facts LIMIT 0","missing",100,100000,false),
        ("source_changed","SELECT v FROM facts","source_changed",100,100000,false),
    ];
    let mut records=Vec::new();
    for (dialect_name,dialect) in [("native",SqlDialect::NativeV1),("010",SqlDialect::DexSql010),("011",SqlDialect::DexSql011)] {
        for (id,sql,mode,rows,steps,cancel) in cases {
            records.push(json!({"dialect":dialect_name,"case":id,"sql":sql,"result":run(dialect,sql,mode,rows,steps,cancel)}));
        }
    }
    println!("{}",json!({"records":records,"profile_admitted":false,
        "scope":"synthetic provider, scalar and aggregate SQL bridge; errors injected, no full facts or transport qualification"}));
}
