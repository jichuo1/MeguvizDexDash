use mdd_sql::{SqlBridge,control::{SqlControl,SqlLimits},dialects::SqlDialect,provider::{SqlBinding,SqlColumn,SqlFactCursor,SqlFactProvider,SqlRelation,SqlRow},values::{SqlType,SqlValue}};
use mdd_types::{DecimalU64,MddResult};
use std::sync::Arc;

struct Provider { binding: SqlBinding }
struct Cursor { rows: std::vec::IntoIter<SqlRow> }
impl SqlFactCursor for Cursor {
    fn next_row(&mut self)->MddResult<Option<SqlRow>>{Ok(self.rows.next())}
}
impl SqlFactProvider for Provider {
    fn binding(&self)->&SqlBinding{&self.binding}
    fn relations(&self)->MddResult<Vec<SqlRelation>>{
        Ok(vec![SqlRelation{name:"code_items".into(),columns:["file_id","method_idx","insns_off","insns_size"].into_iter().map(|name|SqlColumn{id:name.into(),name:name.into(),data_type:SqlType::U64,nullable:name=="method_idx"}).collect(),required_layers:vec![],estimated_rows:Some(DecimalU64(7))}])
    }
    fn require_relation(&self,_:&str)->MddResult<()>{Ok(())}
    fn open_cursor(self:Arc<Self>,_:&str,_:SqlControl)->MddResult<Box<dyn SqlFactCursor>>{
        let indices=[None,Some(0),Some(1),Some(8),Some(9),Some(8),Some(12)];
        let rows=indices.into_iter().map(|i|vec![SqlValue::U64(DecimalU64(0)),i.map_or(SqlValue::Null,|n|SqlValue::U64(DecimalU64(n))),SqlValue::U64(DecimalU64(42)),SqlValue::U64(DecimalU64(1))]).collect::<Vec<_>>();
        Ok(Box::new(Cursor{rows:rows.into_iter()}))
    }
}
fn main(){
    let queries=[
        ("q09_range","SELECT method_idx,insns_off,insns_size FROM code_items WHERE file_id=0 AND method_idx BETWEEN 0 AND 8 ORDER BY method_idx"),
        ("q09_empty","SELECT method_idx FROM code_items WHERE file_id=0 AND method_idx BETWEEN 20 AND 30 ORDER BY method_idx"),
        ("duplicates","SELECT COUNT(*) AS n FROM code_items WHERE method_idx BETWEEN 8 AND 8"),
        ("null_projection","SELECT method_idx,method_idx BETWEEN 0 AND 8 AS n FROM code_items ORDER BY method_idx"),
        ("not_between","SELECT method_idx FROM code_items WHERE method_idx NOT BETWEEN 0 AND 8 ORDER BY method_idx"),
        ("text_bounds","SELECT method_idx FROM code_items WHERE method_idx BETWEEN '0' AND '8' ORDER BY method_idx"),
        ("null_lower","SELECT method_idx,method_idx BETWEEN NULL AND 8 AS n FROM code_items ORDER BY method_idx"),
        ("null_upper","SELECT method_idx,method_idx BETWEEN 0 AND NULL AS n FROM code_items ORDER BY method_idx"),
        ("literal_mixed","SELECT 1 BETWEEN '0' AND '8' AS a,1 NOT BETWEEN '0' AND '8' AS b"),
    ];
    let mut records=Vec::new();
    for dialect in [SqlDialect::NativeV1,SqlDialect::DexSql010,SqlDialect::DexSql011] {
        let provider=Arc::new(Provider{binding:SqlBinding{provider_identity:"q09-synthetic".into(),snapshot_id:"synthetic-snapshot".into(),catalog_epoch:DecimalU64(0)}});
        let bridge=SqlBridge::new(provider,dialect,SqlLimits::default()).unwrap();
        for (name,sql) in queries {
            let output=match bridge.query(sql){Ok(x)=>serde_json::json!({"status":"ok","result":x}),Err(e)=>serde_json::json!({"status":"error","error":e})};
            records.push(serde_json::json!({"dialect":format!("{dialect:?}"),"case":name,"sql":sql,"output":output}));
        }
    }
    println!("{}",serde_json::json!({"records":records,"profiles_admitted":false,"scope":"synthetic Q09 and BETWEEN/NULL; no production facts"}));
}
