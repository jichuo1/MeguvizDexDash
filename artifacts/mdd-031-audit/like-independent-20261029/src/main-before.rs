use mdd_sql::{
    SqlBridge,
    control::{SqlControl, SqlLimits},
    dialects::SqlDialect,
    provider::{SqlBinding, SqlFactCursor, SqlFactProvider, SqlRelation},
    values::SqlValue,
};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{sync::Arc, time::{Duration, Instant}};

struct Empty(SqlBinding);
impl SqlFactProvider for Empty {
    fn binding(&self) -> &SqlBinding { &self.0 }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> { Ok(vec![]) }
    fn require_relation(&self, _: &str) -> MddResult<()> {
        Err(MddError::new(ErrorCode::InvalidArgument, "fixture", "unexpected relation"))
    }
    fn open_cursor(self: Arc<Self>, _: &str, _: SqlControl) -> MddResult<Box<dyn SqlFactCursor>> {
        Err(MddError::new(ErrorCode::InvalidArgument, "fixture", "unexpected cursor"))
    }
}

fn execute(dialect: SqlDialect, sql: &str, args: &[SqlValue], limits: SqlLimits, mode: &str) -> Value {
    let provider = Arc::new(Empty(SqlBinding { provider_identity: "synthetic-like".into(),
        snapshot_id: "fixture-only".into(), catalog_epoch: DecimalU64(0) }));
    let bridge = SqlBridge::new(provider, dialect, limits).unwrap();
    let prepared = match bridge.prepare_with_parameters(sql, args) {
        Ok(p) => p,
        Err(e) => return json!({"status":"prepare_error", "error":e}),
    };
    let deadline = if mode == "deadline" { Some(Instant::now()) } else { None };
    let control = SqlControl::new(limits, deadline);
    if mode == "cancelled" { control.cancel().unwrap(); }
    let cancellation = if mode == "async_cancel" {
        let token = control.clone();
        Some(std::thread::spawn(move || { std::thread::sleep(Duration::from_millis(1)); token.cancel().unwrap(); }))
    } else { None };
    let result = match bridge.execute(&prepared, control) {
        Ok(v) => json!({"status":"ok", "result":v}),
        Err(e) => json!({"status":"error", "error":e}),
    };
    if let Some(thread) = cancellation { thread.join().unwrap(); }
    result
}

fn main() {
    let mut records = Vec::new();
    for (name, dialect) in [("native", SqlDialect::NativeV1), ("010", SqlDialect::DexSql010), ("011", SqlDialect::DexSql011)] {
        let long = SqlValue::text(&"x".repeat(100_000));
        let empty = SqlValue::text("");
        let query = "SELECT ?1 LIKE ?2 AS matched";
        let small = SqlLimits { max_steps: 50, ..SqlLimits::default() };
        let normal = SqlLimits::default();
        let cases = vec![
            ("long_empty_low_budget", query, vec![empty.clone(), long.clone()], small, "normal"),
            ("long_empty_sufficient_budget", query, vec![empty.clone(), long.clone()], normal, "normal"),
            ("short_match", query, vec![SqlValue::text("Abc"), SqlValue::text("a%c")], normal, "normal"),
            ("null_input", query, vec![SqlValue::Null, SqlValue::text("%")], normal, "normal"),
            ("cancelled", query, vec![empty.clone(), empty.clone()], normal, "cancelled"),
            ("deadline", query, vec![empty.clone(), empty.clone()], normal, "deadline"),
            ("async_cancel", query, vec![empty.clone(), long.clone()], normal, "async_cancel"),
            ("dangling_escape", "SELECT ?1 LIKE ?2 ESCAPE ?3 AS matched", vec![SqlValue::text("ab"), SqlValue::text("ab\\"), SqlValue::text("\\")], normal, "normal"),
            ("escaped_percent", "SELECT ?1 LIKE ?2 ESCAPE ?3 AS matched", vec![SqlValue::text("a%b"), SqlValue::text("a\\%b"), SqlValue::text("\\")], normal, "normal"),
        ];
        for (case, sql, args, limits, mode) in cases {
            records.push(json!({"dialect":name, "case":case, "result":execute(dialect, sql, &args, limits, mode)}));
        }
    }
    println!("{}", json!({"scope":"synthetic standalone public bridge; not profile or worker qualification", "records":records}));
}
