use mdd_query::ir::Signed64;
use mdd_sql::{
    SqlBridge,
    control::{SqlControl, SqlLimits},
    dialects::SqlDialect,
    provider::{SqlBinding, SqlColumn, SqlFactCursor, SqlFactProvider, SqlRelation, SqlRow},
    values::{SqlType, SqlValue},
};
use mdd_types::{DecimalU64, MddResult};
use std::sync::Arc;

fn integer(x: i64) -> SqlValue { SqlValue::I64(Signed64(x)) }
fn column(name: &str, ty: SqlType, nullable: bool) -> SqlColumn {
    SqlColumn { id: name.into(), name: name.into(), data_type: ty, nullable }
}
struct Provider { binding: SqlBinding }
struct Cursor { rows: std::vec::IntoIter<SqlRow> }
impl SqlFactCursor for Cursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> { Ok(self.rows.next()) }
}
impl SqlFactProvider for Provider {
    fn binding(&self) -> &SqlBinding { &self.binding }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        let m = [("file_id",SqlType::I64),("method_idx",SqlType::I64),("class",SqlType::Text),("name",SqlType::Text),("proto",SqlType::Text),("access",SqlType::Text),("code_size",SqlType::I64)];
        let d = [("file_id",SqlType::I64),("source",SqlType::Text),("member",SqlType::Text),("size",SqlType::I64),("n_classes",SqlType::I64),("n_method_ids",SqlType::I64),("n_field_ids",SqlType::I64),("n_strings",SqlType::I64)];
        Ok(vec![SqlRelation { name:"methods".into(), columns:m.iter().map(|(n,t)|column(n,*t,true)).collect(),required_layers:vec![], estimated_rows:None },
                SqlRelation { name:"dex_files".into(), columns:d.iter().map(|(n,t)|column(n,*t,*n!="file_id")).collect(),required_layers:vec![],estimated_rows:None }])
    }
    fn require_relation(&self, _: &str) -> MddResult<()> { Ok(()) }
    fn open_cursor(self: Arc<Self>, relation: &str, _: SqlControl) -> MddResult<Box<dyn SqlFactCursor>> {
        let txt = SqlValue::text;
        let rows = match relation {
            "methods" => vec![
                vec![integer(1),integer(1),txt("LA;"),txt("f"),txt("()V"),txt("public"),integer(4)],
                vec![integer(1),integer(2),txt("LA;"),txt("f"),txt("()V"),txt("public"),integer(8)],
                vec![integer(2),integer(3),txt("LA;"),txt("f"),txt("()V"),txt("public"),integer(1)],
                vec![integer(3),integer(4),txt("LA;"),txt("f"),txt("()V"),txt("public"),integer(1)],
                vec![integer(2),integer(5),txt("LA;"),txt("g"),txt("()V"),txt("public"),integer(1)]],
            "dex_files" => vec![
                vec![integer(1),txt("one.apk"),txt("classes.dex"),integer(3),integer(1),integer(2),integer(0),integer(3)],
                vec![integer(2),txt("two.dex"),SqlValue::Null,integer(3),integer(1),integer(2),integer(0),integer(3)]],
            _ => vec![],
        };
        Ok(Box::new(Cursor { rows: rows.into_iter() }))
    }
}
fn main() -> Result<(),Box<dyn std::error::Error>> {
    let provider = Arc::new(Provider { binding: SqlBinding { provider_identity:"independent-fixture".into(),snapshot_id:"synthetic-only".into(),catalog_epoch:DecimalU64(0) }});
    let bridge = SqlBridge::new(provider,SqlDialect::NativeV1,SqlLimits::default())?;
    let sql = "SELECT m.file_id, d.source, d.member FROM methods m JOIN dex_files d USING(file_id) WHERE m.class=? AND m.name=? AND m.proto=?";
    let prepared = bridge.prepare_with_parameters(sql, &[SqlValue::text("LA;"),SqlValue::text("f"),SqlValue::text("()V")])?;
    let output = bridge.execute(&prepared,SqlControl::new(SqlLimits::default(),None))?;
    println!("{}",serde_json::to_string(&output)?);
    Ok(())
}
