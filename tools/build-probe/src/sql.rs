use rusqlite::types::{Value, ValueRef};
use rusqlite::vtab::{Context, Filters, IndexInfo, Module, VTab, VTabConnection, VTabCursor};
use rusqlite::{Connection, Result, ffi};
use serde_json::{Value as Json, json};
use std::borrow::Cow;
use std::ffi::{CStr, CString, c_int};
use std::sync::Arc;

struct Table {
    schema: CString,
    rows: Vec<Vec<Value>>,
}

#[repr(C)]
struct FactTable {
    base: ffi::sqlite3_vtab,
    table: Arc<Table>,
}

// SAFETY: repr(C) puts SQLite's base first. All table data is owned by Arc,
// immutable, and retained independently by each cursor until SQLite closes it.
unsafe impl<'vtab> VTab<'vtab> for FactTable {
    type Aux = Arc<Table>;
    type Cursor = FactCursor;

    fn connect(
        _: &mut VTabConnection,
        aux: Option<&Self::Aux>,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[&[u8]],
    ) -> Result<(Cow<'static, CStr>, Self)> {
        let table = Arc::clone(aux.ok_or_else(|| {
            rusqlite::Error::ModuleError("missing immutable fact source".to_owned())
        })?);
        Ok((
            Cow::Owned(table.schema.clone()),
            Self {
                base: ffi::sqlite3_vtab::default(),
                table,
            },
        ))
    }

    fn best_index(&self, info: &mut IndexInfo) -> Result<bool> {
        info.set_estimated_cost(self.table.rows.len() as f64 + 1.0);
        info.set_estimated_rows(self.table.rows.len() as i64);
        info.set_order_by_consumed(false);
        // No constraint claims and no LIMIT/OFFSET pushdown: SQLite applies
        // residual predicates and sorting to the complete immutable scan.
        Ok(true)
    }

    fn open(&mut self) -> Result<Self::Cursor> {
        Ok(FactCursor {
            base: ffi::sqlite3_vtab_cursor::default(),
            table: Arc::clone(&self.table),
            row: 0,
        })
    }
}

#[repr(C)]
struct FactCursor {
    base: ffi::sqlite3_vtab_cursor,
    table: Arc<Table>,
    row: usize,
}

// SAFETY: repr(C) puts the SQLite cursor base first. No borrowed source memory
// crosses the callback, and every column access is bounds checked.
unsafe impl VTabCursor for FactCursor {
    fn filter(&mut self, _: c_int, _: Option<&str>, _: &Filters<'_>) -> Result<()> {
        self.row = 0;
        Ok(())
    }

    fn next(&mut self) -> Result<()> {
        self.row += 1;
        Ok(())
    }

    fn eof(&self) -> bool {
        self.row >= self.table.rows.len()
    }

    fn column(&self, context: &mut Context, column: c_int) -> Result<()> {
        let value = usize::try_from(column)
            .ok()
            .and_then(|column| self.table.rows.get(self.row)?.get(column))
            .ok_or_else(|| rusqlite::Error::ModuleError("invalid fact coordinate".to_owned()))?;
        context.set_result(value)
    }

    fn rowid(&self) -> Result<i64> {
        Ok(self.row as i64 + 1)
    }
}

fn register(db: &Connection, name: &CStr, schema: &str, rows: Vec<Vec<Value>>) -> Result<()> {
    const MODULE: Module<FactTable> = Module::eponymous_only_module();
    let schema =
        CString::new(schema).map_err(|error| rusqlite::Error::ModuleError(error.to_string()))?;
    db.create_module(name, &MODULE, Some(Arc::new(Table { schema, rows })))
}

fn number(value: i64) -> Value {
    Value::Integer(value)
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn query(db: &Connection, sql: &str) -> Result<Json> {
    let mut statement = db.prepare(sql)?;
    let column_count = statement.column_count();
    let columns: Vec<_> = statement
        .column_names()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut cursor = statement.query([])?;
    let mut rows = Vec::new();
    while let Some(row) = cursor.next()? {
        let mut cells = Vec::new();
        for column in 0..column_count {
            cells.push(match row.get_ref(column)? {
                ValueRef::Null => Json::Null,
                ValueRef::Integer(value) => json!(value),
                ValueRef::Real(value) => json!({"sqlite_real": value}),
                ValueRef::Text(value) => match str::from_utf8(value) {
                    Ok(value) => json!(value),
                    Err(_) => json!({"invalid_utf8_sqlite_text_bytes": value}),
                },
                ValueRef::Blob(value) => json!({"bytes": value}),
            });
        }
        rows.push(cells);
    }
    Ok(json!({"columns": columns, "rows": rows}))
}

fn case(db: &Connection, id: &str, sql: &str, expected: Json, basis: &str) -> Result<Json> {
    match query(db, sql) {
        Ok(actual) => Ok(
            json!({"id": id, "sql": sql, "basis": basis, "expected_rows": expected,
            "actual": actual, "passed": actual["rows"] == expected}),
        ),
        Err(error) => Ok(
            json!({"id": id, "sql": sql, "basis": basis, "expected_rows": expected,
            "actual_error": error.to_string(), "passed": false}),
        ),
    }
}

fn corpus_case(db: &Connection, id: &str, expected: Json) -> Result<Json> {
    for line in include_str!("../../../conformance/corpus/hostlab/queries.jsonl").lines() {
        let item: Json = serde_json::from_str(line)
            .map_err(|error| rusqlite::Error::ModuleError(error.to_string()))?;
        if item["id"] == id {
            let sql = item["representative_sql"].as_str().ok_or_else(|| {
                rusqlite::Error::ModuleError(format!("{id} missing representative SQL"))
            })?;
            let mut observed = case(
                db,
                &format!("{id}-frozen-corpus"),
                sql,
                expected,
                "冻结源码corpus原样执行，参数为该corpus登记的合成fixture值；不是生产golden",
            )?;
            observed["source_commit"] = item["source_commit"].clone();
            observed["corpus_path"] = json!("conformance/corpus/hostlab/queries.jsonl");
            return Ok(observed);
        }
    }
    Err(rusqlite::Error::ModuleError(format!(
        "{id} not found in frozen corpus"
    )))
}

pub fn probe() -> std::result::Result<Json, Box<dyn std::error::Error>> {
    let db = Connection::open_in_memory()?;
    register(
        &db,
        c"dex_files",
        "CREATE TABLE x(file_id INTEGER,entry_name TEXT,string_pool_id INTEGER)",
        vec![
            vec![number(0), text("classes.dex"), number(10)],
            vec![number(1), text("classes2.dex"), number(11)],
        ],
    )?;
    register(
        &db,
        c"classes",
        "CREATE TABLE x(file_id INTEGER,class_idx INTEGER,descriptor TEXT)",
        vec![
            vec![number(0), number(1), text("Lfixture/A;")],
            vec![number(1), number(1), text("Lfixture/B;")],
        ],
    )?;
    register(
        &db,
        c"class_interfaces",
        "CREATE TABLE x(file_id INTEGER,class_idx INTEGER,interface_descriptor TEXT,ordinal INTEGER)",
        vec![
            vec![number(0), number(1), text("Lsample/I;"), number(0)],
            vec![number(1), number(1), text("Lsample/J;"), number(0)],
        ],
    )?;
    register(
        &db,
        c"class_methods",
        "CREATE TABLE x(file_id INTEGER,method_idx INTEGER,method_name TEXT)",
        vec![
            vec![number(0), number(3), text("run")],
            vec![number(1), number(3), text("run")],
        ],
    )?;
    register(
        &db,
        c"methods",
        "CREATE TABLE x(file_id INTEGER,method_idx INTEGER,return_descriptor TEXT,class_descriptor TEXT)",
        vec![
            vec![
                number(0),
                number(3),
                text("Lfixture/Result;"),
                text("Lfixture/A;"),
            ],
            vec![number(1), number(3), text("I"), text("Lfixture/B;")],
        ],
    )?;
    register(
        &db,
        c"method_calls",
        "CREATE TABLE x(file_id INTEGER,method_idx INTEGER,callee TEXT,method TEXT,callee_class TEXT)",
        vec![
            vec![
                number(0),
                number(3),
                text("Lfixture/T;->f()V"),
                text("Lfixture/A;->run()V"),
                text("Lfixture/T;"),
            ],
            vec![
                number(0),
                number(3),
                text("Lfixture/T;->f()V"),
                text("Lfixture/A;->run()V"),
                text("Lfixture/T;"),
            ],
            vec![
                number(1),
                number(3),
                text("Lfixture/T;->f()V"),
                text("Lfixture/B;->run()V"),
                text("Lfixture/T;"),
            ],
        ],
    )?;
    register(
        &db,
        c"method_strings",
        "CREATE TABLE x(file_id INTEGER,method_idx INTEGER,method_class TEXT,value TEXT)",
        vec![
            vec![
                number(0),
                number(3),
                text("Lfixture/A;"),
                text("quality settings: fixture"),
            ],
            vec![number(0), number(3), text("Lfixture/A;"), text("unrelated")],
        ],
    )?;
    register(
        &db,
        c"strings",
        "CREATE TABLE x(string_pool_id INTEGER,string_idx INTEGER,text TEXT)",
        vec![
            vec![number(10), number(0), Value::Null],
            vec![number(10), number(1), text("")],
            vec![number(10), number(2), text("A\0B")],
            vec![number(10), number(3), text("a_b")],
            vec![number(10), number(4), text("axb")],
        ],
    )?;
    let mut cases = vec![
        case(
            &db,
            "Q01",
            "SELECT file_id,entry_name FROM dex_files ORDER BY file_id",
            json!([[0, "classes.dex"], [1, "classes2.dex"]]),
            "真实Q01 SQL；合成不可变事实",
        )?,
        case(
            &db,
            "Q03-shape",
            "SELECT c.descriptor,ci.interface_descriptor FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx ORDER BY c.file_id",
            json!([["Lfixture/A;", "Lsample/I;"], ["Lfixture/B;", "Lsample/J;"]]),
            "Q03 双局部键JOIN形状；不冒充实际HostLab完整展开语句",
        )?,
        case(
            &db,
            "Q05-shape",
            "SELECT DISTINCT cm.file_id,cm.method_idx,m.return_descriptor FROM class_methods cm JOIN methods m ON cm.file_id=m.file_id AND cm.method_idx=m.method_idx ORDER BY cm.file_id",
            json!([[0, 3, "Lfixture/Result;"], [1, 3, "I"]]),
            "Q05 JOIN+DISTINCT；相同局部method_idx跨DEX",
        )?,
        case(
            &db,
            "Q07",
            "SELECT COUNT(*) AS n FROM classes ORDER BY n",
            json!([[2]]),
            "真实Q07 SQL；合成事实",
        )?,
        case(
            &db,
            "Q10-shape",
            "SELECT file_id,method_idx,callee,COUNT(*) AS n FROM method_calls GROUP BY file_id,method_idx,callee ORDER BY file_id,method_idx,callee",
            json!([
                [0, 3, "Lfixture/T;->f()V", 2],
                [1, 3, "Lfixture/T;->f()V", 1]
            ]),
            "Q10 GROUP BY/COUNT形状，重复调用点保留",
        )?,
        case(
            &db,
            "null-cast",
            "SELECT COUNT(*),COUNT(text),hex(CAST(NULL AS TEXT)),CAST(9223372036854775807 AS TEXT) FROM strings",
            json!([[5, 4, "", "9223372036854775807"]]),
            "SQLite NULL/CAST/i64探针；不是DexSQL差分资格",
        )?,
        case(
            &db,
            "cte-in-between",
            "WITH ids AS (SELECT file_id FROM classes WHERE file_id BETWEEN 0 AND 1) SELECT file_id FROM ids WHERE file_id IN (0,1) ORDER BY file_id DESC LIMIT 1 OFFSET 1",
            json!([[0]]),
            "CTE/IN/BETWEEN/ORDER/LIMIT/OFFSET",
        )?,
        case(
            &db,
            "like-escape",
            "SELECT text FROM strings WHERE text LIKE 'a\\_b' ESCAPE '\\' ORDER BY string_idx",
            json!([["a_b"]]),
            "显式ESCAPE必须精确保留",
        )?,
        case(
            &db,
            "duplicate-column-names",
            "SELECT file_id AS x,class_idx AS x FROM classes ORDER BY file_id",
            json!([[0, 1], [1, 1]]),
            "ordinal列避免dictionary覆盖重复列名",
        )?,
        case(
            &db,
            "nul-length-native-gap",
            "SELECT length(text),hex(CAST(text AS BLOB)) FROM strings WHERE string_idx=2",
            json!([[3, "410042"]]),
            "mdd-text-v1 UTF16 code units预期3；SQLite默认length在NUL截止，是已验证反例",
        )?,
        case(
            &db,
            "like-underscore-compat-gap",
            "SELECT text FROM strings WHERE text LIKE 'a_b' ORDER BY string_idx",
            json!([["a_b"]]),
            "工程包记录DexSQL0.1.1 '_'字面值例外；SQLite默认 '_'通配符，兼容需适配",
        )?,
        case(
            &db,
            "utf16-order-native-gap",
            "SELECT v FROM (SELECT char(65536) AS v UNION ALL SELECT char(57344)) ORDER BY v",
            json!([["\u{10000}"], ["\u{e000}"]]),
            "mdd-text-v1按UTF16 units排序；SQLite默认UTF8 BINARY顺序不同",
        )?,
    ];
    let write_error = db
        .execute("DELETE FROM classes", [])
        .err()
        .map(|e| e.to_string());
    cases.push(
        json!({"id": "read-only-facts", "sql": "DELETE FROM classes",
        "passed": write_error.is_some(), "actual_error": write_error}),
    );
    let invalid_text = query(&db, "SELECT CAST(x'EDA080' AS TEXT) AS lone_surrogate")?;
    let lossless_json_text = invalid_text["rows"][0][0].as_str().is_some();
    cases.push(json!({"id":"lone-surrogate-representation-gap", "sql":"SELECT CAST(x'EDA080' AS TEXT)",
        "passed": lossless_json_text, "actual": invalid_text,
        "reason":"SQLite TEXT permits invalid UTF8 byte sequences; strict JSON needs tagged raw MUTF8/UTF16 and explicit CAST semantics"}));
    db.execute_batch("CREATE TEMP TABLE saved AS SELECT * FROM classes;")?;
    let temp_type: String = db.query_row(
        "SELECT type FROM sqlite_temp_master WHERE name='saved'",
        [],
        |r| r.get(0),
    )?;
    cases.push(json!({"id":"temp-definition-gap", "passed":temp_type == "view", "actual_sqlite_object_type":temp_type,
        "reason":"SQLite CTAS materializes a table; project contract requires parsed query definition plus versioned session catalog, not implemented"}));
    cases.extend([
        corpus_case(&db, "Q01", json!([[0, "classes.dex"], [1, "classes2.dex"]]))?,
        corpus_case(&db, "Q03", json!([["Lsample/I;", "Lfixture/A;"]]))?,
        corpus_case(&db, "Q05", json!([["Lfixture/A;"]]))?,
        corpus_case(&db, "Q06", json!([[0, 3, "quality settings: fixture"]]))?,
        corpus_case(&db, "Q07", json!([[2]]))?,
        corpus_case(
            &db,
            "Q10",
            json!([[0, "Lfixture/A;->run()V", "Lfixture/T;->f()V", 2]]),
        )?,
    ]);
    let passed = cases.iter().filter(|case| case["passed"] == true).count();
    Ok(
        json!({"schema_version":"mdd.sql-bridge-probes.v1", "record_kind":"observed_dependency_probe",
        "sqlite_version":rusqlite::version(), "rusqlite_version":"0.40.2", "implementation":"Rust eponymous-only read-only virtual tables over Arc-owned rows",
        "fact_source":"manually specified synthetic rows, not a DEX parser",
        "platform":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH},
        "optimizer":{"omit":false,"order_by_consumed":false,"limit_offset_pushdown":false},
        "cases":cases, "passed_cases":passed,"total_cases":cases.len(),
        "profiles_admitted":[], "hostlab_qualification":false,
        "remaining":["complete actual HostLab corpus and production inputs","lossless DexText SQL value/CAST/LIKE/length/collation adaptation","versioned TEMP catalog and cursor lifecycle","budget/cancellation/snapshot facts integration"]}),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn sqlite_vtable_probe_records_successes_and_real_gaps() {
        let result = super::probe().unwrap();
        let cases = result["cases"].as_array().unwrap();
        let get = |id: &str| cases.iter().find(|case| case["id"] == id).unwrap();
        assert_eq!(result["hostlab_qualification"], false);
        assert_eq!(
            get("Q03-shape")["actual"]["rows"].as_array().unwrap().len(),
            2
        );
        assert_eq!(get("Q10-shape")["actual"]["rows"][0][3], 2);
        assert_eq!(
            get("duplicate-column-names")["actual"]["columns"],
            serde_json::json!(["x", "x"])
        );
        assert_eq!(
            get("nul-length-native-gap")["actual"]["rows"][0],
            serde_json::json!([1, "410042"])
        );
        assert_eq!(
            get("like-underscore-compat-gap")["actual"]["rows"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            get("utf16-order-native-gap")["actual"]["rows"][0][0],
            "\u{e000}"
        );
        assert_eq!(
            get("lone-surrogate-representation-gap")["actual"]["rows"][0][0]["invalid_utf8_sqlite_text_bytes"],
            serde_json::json!([237, 160, 128])
        );
        assert_eq!(
            get("temp-definition-gap")["actual_sqlite_object_type"],
            "table"
        );
        assert!(
            get("read-only-facts")["actual_error"]
                .as_str()
                .unwrap()
                .contains("may not be modified")
        );
        assert_eq!(get("Q01-frozen-corpus")["passed"], true);
        assert_eq!(get("Q03-frozen-corpus")["passed"], true);
        assert_eq!(get("Q05-frozen-corpus")["passed"], true);
        assert_eq!(get("Q06-frozen-corpus")["passed"], true);
        assert_eq!(get("Q07-frozen-corpus")["passed"], true);
        assert_eq!(get("Q10-frozen-corpus")["passed"], true);
    }
}
