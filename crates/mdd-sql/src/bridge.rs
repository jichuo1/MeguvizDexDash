use crate::{
    control::{SqlControl, SqlLimits},
    dialects::SqlDialect,
    invalid,
    provider::{SqlBinding, SqlFactProvider, SqlRelation},
    quota, sqlite_error,
    values::SqlValue,
    virtual_tables::{self, Source},
};
use mdd_query::ir::FactLayer;
use mdd_types::{ErrorCode, MddError, MddResult};
use rusqlite::{
    Connection,
    config::DbConfig,
    hooks::{AuthAction, AuthContext, Authorization},
    limits::Limit,
};
use serde::Serialize;
use std::{collections::BTreeSet, sync::Arc};

pub struct SqlBridge {
    provider: Arc<dyn SqlFactProvider>,
    dialect: SqlDialect,
    limits: SqlLimits,
}
pub struct PreparedSql {
    binding: SqlBinding,
    sql: String,
    adapted_sql: String,
    parameters: Vec<SqlValue>,
    ast_nodes: usize,
    required_relations: Vec<String>,
    required_layers: Vec<FactLayer>,
    relations: Vec<SqlRelation>,
    provider: Arc<dyn SqlFactProvider>,
    dialect: SqlDialect,
    limits: SqlLimits,
    display_overrides: std::collections::BTreeMap<String, String>,
    execution_binding: Option<crate::runtime::SqlExecutionBinding>,
}
#[derive(Debug, Serialize)]
pub struct SqlResult {
    pub binding: SqlBinding,
    pub dialect: SqlDialect,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<SqlValue>>,
    pub calculation_complete: bool,
    pub profiles_admitted: Vec<String>,
    pub sqlite_version: String,
    pub optimizer: OptimizerPolicy,
    pub required_relations: Vec<String>,
    pub required_layers: Vec<FactLayer>,
    pub ast_nodes: usize,
    pub execution_binding: Option<crate::runtime::SqlExecutionBinding>,
}
#[derive(Debug, Serialize)]
pub struct OptimizerPolicy {
    pub omit: bool,
    pub order_by_consumed: bool,
    pub limit_offset_pushdown: bool,
    pub in_pushdown: bool,
}
impl PreparedSql {
    pub fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    pub fn sql(&self) -> &str {
        &self.sql
    }
    pub fn required_relations(&self) -> &[String] {
        &self.required_relations
    }
    pub fn required_layers(&self) -> &[FactLayer] {
        &self.required_layers
    }
    pub fn runtime_query_binding(&self) -> MddResult<mdd_session::QueryBinding> {
        let request=serde_json::to_vec(&serde_json::json!({"binding":self.binding,"sql":self.sql,"parameters":self.parameters,"dialect":self.dialect})).map_err(|_|invalid("SQL_REQUEST_BINDING_ENCODING"))?;
        let schema=serde_json::to_vec(&serde_json::json!({"codec":"mdd.sql.dynamic-values.v1","relations":self.relations,"projection_plan":self.adapted_sql,"display_names":self.display_overrides})).map_err(|_|invalid("SQL_SCHEMA_BINDING_ENCODING"))?;
        Ok(mdd_session::QueryBinding {
            request_key: mdd_types::sha256(&request),
            schema_id: format!("mdd.sql.dynamic-rows.v1:{}", mdd_types::sha256(&schema)),
            semantic_version: format!("mdd.sql.ast.v1;mdd.sql.values.v1;{:?}", self.dialect),
        })
    }
    pub fn bind_runtime(mut self, runtime: &mdd_query::budget::RuntimeBudget) -> MddResult<Self> {
        if self.execution_binding.is_some() {
            return Err(invalid("SQL_PREPARED_ALREADY_RUNTIME_BOUND"));
        }
        self.execution_binding = Some(crate::runtime::SqlExecutionBinding::capture(
            runtime,
            &self.binding,
            &self.runtime_query_binding()?,
        )?);
        Ok(self)
    }
    /// Execute the pinned generation. Higher session/worker APIs must validate
    /// their owner/query lease before invoking this low-level method.
    pub fn execute(&self, control: SqlControl) -> MddResult<SqlResult> {
        SqlBridge::new(Arc::clone(&self.provider), self.dialect, self.limits)?
            .execute(self, control)
    }
}
impl SqlBridge {
    pub fn binding(&self) -> &SqlBinding {
        self.provider.binding()
    }
    pub fn new(
        provider: Arc<dyn SqlFactProvider>,
        dialect: SqlDialect,
        limits: SqlLimits,
    ) -> MddResult<Self> {
        let binding = provider.binding();
        if binding.provider_identity.is_empty() || binding.snapshot_id.is_empty() {
            return Err(invalid("EMPTY_SQL_BINDING"));
        }
        Ok(Self {
            provider,
            dialect,
            limits,
        })
    }
    pub fn prepare(&self, sql: &str) -> MddResult<PreparedSql> {
        self.prepare_with_parameters(sql, &[])
    }
    pub fn prepare_with_parameters(
        &self,
        sql: &str,
        parameters: &[SqlValue],
    ) -> MddResult<PreparedSql> {
        let relations = self.provider.relations()?;
        let mut names = BTreeSet::new();
        for relation in &relations {
            if relation.name.is_empty()
                || relation.name.contains('\0')
                || !names.insert(relation.name.to_ascii_lowercase())
                || relation.columns.is_empty()
            {
                return Err(invalid("PROVIDER_RELATION_SCHEMA"));
            }
            let mut columns = BTreeSet::new();
            for column in &relation.columns {
                if column.name.is_empty()
                    || column.name.contains('\0')
                    || !columns.insert(column.name.to_ascii_lowercase())
                {
                    return Err(invalid("PROVIDER_COLUMN_SCHEMA"));
                }
            }
        }
        let adapted = match crate::dialects::ast::adapt(
            sql,
            self.limits,
            parameters,
            &relations,
            self.dialect,
        ) {
            Ok(adapted) => adapted,
            Err(error)
                if error.details.get("confirm_sqlite_syntax")
                    == Some(&serde_json::Value::Bool(true)) =>
            {
                if let Some(cause) = self.original_binding_error(sql, &relations)? {
                    return Err(cause.detail("ast_error", error.message));
                }
                return Err(MddError::new(ErrorCode::UnsupportedQuery,"sql.ast","SQLite accepts this read-only syntax but the AST adapter does not yet implement it").detail("ast_error",error.message));
            }
            Err(error) => return Err(error),
        };
        for required in &adapted.required_relations {
            if !relations
                .iter()
                .any(|r| r.name.eq_ignore_ascii_case(required))
            {
                return Err(invalid("UNKNOWN_RELATION").detail("relation", required.clone()));
            }
        }
        let required_layers = relations
            .iter()
            .filter(|r| {
                adapted
                    .required_relations
                    .iter()
                    .any(|name| r.name.eq_ignore_ascii_case(name))
            })
            .flat_map(|r| r.required_layers.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(PreparedSql {
            binding: self.provider.binding().clone(),
            sql: sql.to_owned(),
            adapted_sql: adapted.sql,
            parameters: adapted.parameters,
            ast_nodes: adapted.nodes,
            required_relations: adapted.required_relations,
            required_layers,
            relations,
            provider: Arc::clone(&self.provider),
            dialect: self.dialect,
            limits: self.limits,
            display_overrides: adapted.display_overrides,
            execution_binding: None,
        })
    }
    pub fn execute(&self, prepared: &PreparedSql, control: SqlControl) -> MddResult<SqlResult> {
        if self.provider.binding() != &prepared.binding
            || self.provider.binding() != prepared.provider.binding()
            || self.dialect != prepared.dialect
        {
            return Err(invalid("SQL_PREPARED_GENERATION_OR_DIALECT_CHANGED"));
        }
        let control = control.restrict(self.limits.restricted_by(prepared.limits));
        match (&prepared.execution_binding, control.runtime()) {
            (None, None) => (),
            (Some(expected), Some(runtime)) => {
                let actual = crate::runtime::SqlExecutionBinding::capture(
                    runtime,
                    &prepared.binding,
                    &prepared.runtime_query_binding()?,
                )?;
                if &actual != expected {
                    return Err(invalid("SQL_RUNTIME_OWNER_MISMATCH"));
                }
            }
            _ => {
                return Err(invalid(
                    "SQL_RUNTIME_BINDING_REQUIRED_ON_BOTH_PREPARED_AND_CONTROL",
                ));
            }
        }
        control.claim()?;
        if let Some(runtime) = control.runtime() {
            runtime.cancellation().claim_execution()?;
        }
        let result = self
            .execute_inner(prepared, control.clone())
            .map_err(|error| control.fail(error))?;
        if let Some(runtime) = control.runtime() {
            runtime.cancellation().mark_computed()?;
            if let Some(error) = runtime.cancellation().status()?.error {
                return Err(error
                    .detail("execution_complete", true)
                    .detail("total_rows", result.rows.len().to_string()));
            }
        }
        Ok(result)
    }
    fn execute_inner(&self, prepared: &PreparedSql, control: SqlControl) -> MddResult<SqlResult> {
        control.checkpoint(1, false)?;
        // Scope admission is independent of SQLite short-circuit execution.
        // LIMIT 0 / WHERE false must not turn an unbuilt required layer into
        // an empty successful answer; unused registered relations stay unbuilt.
        for name in &prepared.required_relations {
            prepared.provider.require_relation(name)?;
        }
        let db = Connection::open_in_memory().map_err(sqlite_error)?;
        // SAFETY: the connection is exclusively owned here, has no statements
        // or callbacks in flight, and remains alive throughout this C call.
        // rusqlite's wrapper is feature-gated; enabling extensions is not needed.
        let extension_rc = unsafe { rusqlite::ffi::sqlite3_enable_load_extension(db.handle(), 0) };
        if extension_rc != rusqlite::ffi::SQLITE_OK {
            return Err(sqlite_error(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(extension_rc),
                None,
            )));
        }
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(sqlite_error)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
            .map_err(sqlite_error)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)
            .map_err(sqlite_error)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)
            .map_err(sqlite_error)?;
        db.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
            .map_err(sqlite_error)?;
        db.set_limit(Limit::SQLITE_LIMIT_WORKER_THREADS, 0)
            .map_err(sqlite_error)?;
        db.set_limit(
            Limit::SQLITE_LIMIT_SQL_LENGTH,
            i32::try_from(self.limits.max_sql_bytes.saturating_mul(8)).unwrap_or(i32::MAX),
        )
        .map_err(sqlite_error)?;
        db.set_limit(
            Limit::SQLITE_LIMIT_LENGTH,
            i32::try_from(control.inner.limits.max_cell_bytes.saturating_add(64))
                .unwrap_or(i32::MAX),
        )
        .map_err(sqlite_error)?;
        db.set_limit(
            Limit::SQLITE_LIMIT_EXPR_DEPTH,
            i32::try_from(self.limits.max_ast_depth).unwrap_or(i32::MAX),
        )
        .map_err(sqlite_error)?;
        for relation in &prepared.relations {
            virtual_tables::register(
                &db,
                Arc::new(Source {
                    provider: Arc::clone(&prepared.provider),
                    relation: relation.clone(),
                    binding: prepared.binding.clone(),
                    control: control.clone(),
                }),
            )
            .map_err(sqlite_error)?;
        }
        crate::dialects::functions::register(&db, prepared.dialect, control.clone())
            .map_err(sqlite_error)?;
        let names = prepared
            .relations
            .iter()
            .map(|r| r.name.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        db.authorizer(Some(move |context: AuthContext<'_>| match context.action {
            AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
            AuthAction::Read { table_name, .. }
                if names.contains(&table_name.to_ascii_lowercase()) =>
            {
                Authorization::Allow
            }
            AuthAction::Function { function_name }
                if [
                    "count",
                    "coalesce",
                    "ifnull",
                    "mdd_nullif",
                    "mdd_sum",
                    "mdd_min",
                    "mdd_max",
                    "mdd_length",
                    "mdd_substr",
                    "mdd_hex",
                    "mdd_lower",
                    "mdd_upper",
                    "mdd_eq",
                    "mdd_ne",
                    "mdd_gt",
                    "mdd_ge",
                    "mdd_lt",
                    "mdd_le",
                    "mdd_concat",
                    "mdd_cast",
                    "mdd_add",
                    "mdd_sub",
                    "mdd_mul",
                    "mdd_div",
                    "mdd_mod",
                    "mdd_neg",
                    "mdd_pos",
                    "mdd_key",
                    "mdd_sort_key",
                    "mdd_like",
                    "mdd_truth_input",
                ]
                .iter()
                .any(|f| f.eq_ignore_ascii_case(function_name)) =>
            {
                Authorization::Allow
            }
            _ => Authorization::Deny,
        }))
        .map_err(sqlite_error)?;
        let progress = control.clone();
        db.progress_handler(1, Some(move || progress.checkpoint(1, false).is_err()))
            .map_err(sqlite_error)?;
        let result = (|| {
            let mut statement = db.prepare(&prepared.adapted_sql).map_err(sqlite_error)?;
            if !statement.readonly() {
                return Err(invalid("SQLITE_STATEMENT_NOT_READONLY"));
            }
            let columns = statement
                .column_names()
                .iter()
                .map(|name| {
                    prepared
                        .display_overrides
                        .get(*name)
                        .cloned()
                        .unwrap_or_else(|| (*name).to_owned())
                })
                .collect::<Vec<_>>();
            let parameters = prepared
                .parameters
                .iter()
                .map(|v| v.sqlite(control.inner.limits.max_cell_bytes))
                .collect::<MddResult<Vec<_>>>()?;
            let count = columns.len();
            let mut cursor = statement
                .query(rusqlite::params_from_iter(parameters))
                .map_err(sqlite_error)?;
            let mut rows = Vec::new();
            while let Some(row) = cursor.next().map_err(sqlite_error)? {
                control.checkpoint(1, false)?;
                let mut values = Vec::with_capacity(count);
                let mut bytes = 0u64;
                for ordinal in 0..count {
                    let value_ref = row.get_ref(ordinal).map_err(sqlite_error)?;
                    // Text UTF-8 may expand to two bytes per code unit. Charge
                    // conservatively before allocating an owned result value.
                    let work = match value_ref {
                        rusqlite::types::ValueRef::Text(v) => (v.len() as u64).checked_mul(2),
                        rusqlite::types::ValueRef::Blob(v) => Some(v.len() as u64),
                        _ => Some(16),
                    }
                    .ok_or_else(|| quota("SQL_RESULT_WORK_OVERFLOW"))?;
                    control.work(work)?;
                    let value = SqlValue::from_sqlite(value_ref)?;
                    let size = value.byte_size();
                    if size > control.inner.limits.max_cell_bytes {
                        return Err(quota("SQL_RESULT_CELL_BYTES"));
                    }
                    bytes = bytes
                        .checked_add(size)
                        .ok_or_else(|| quota("SQL_RESULT_BYTES_OVERFLOW"))?;
                    values.push(value);
                }
                control.output(bytes)?;
                rows.push(values);
            }
            if prepared.provider.binding() != &prepared.binding {
                return Err(invalid("SQL_GENERATION_CHANGED_BEFORE_END"));
            }
            control.checkpoint(1, false)?;
            Ok(SqlResult {
                binding: prepared.binding.clone(),
                dialect: prepared.dialect,
                columns,
                rows,
                calculation_complete: true,
                profiles_admitted: Vec::new(),
                sqlite_version: rusqlite::version().to_owned(),
                optimizer: OptimizerPolicy {
                    omit: false,
                    order_by_consumed: false,
                    limit_offset_pushdown: false,
                    in_pushdown: false,
                },
                required_relations: prepared.required_relations.clone(),
                required_layers: prepared.required_layers.clone(),
                ast_nodes: prepared.ast_nodes,
                execution_binding: prepared.execution_binding.clone(),
            })
        })();
        result.map_err(|error| control.error().unwrap_or(error))
    }
    pub fn query(&self, sql: &str) -> MddResult<SqlResult> {
        let prepared = self.prepare(sql)?;
        self.execute(&prepared, SqlControl::new(self.limits, None))
    }
    /// Only prepare, never step a statement or open facts. This separates a
    /// real syntax/binding error from a gap in the additional AST frontend.
    fn original_binding_error(
        &self,
        sql: &str,
        relations: &[SqlRelation],
    ) -> MddResult<Option<MddError>> {
        let db = Connection::open_in_memory().map_err(sqlite_error)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(sqlite_error)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)
            .map_err(sqlite_error)?;
        db.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
            .map_err(sqlite_error)?;
        let control = SqlControl::new(self.limits, None);
        for relation in relations {
            virtual_tables::register(
                &db,
                Arc::new(Source {
                    provider: Arc::clone(&self.provider),
                    relation: relation.clone(),
                    binding: self.provider.binding().clone(),
                    control: control.clone(),
                }),
            )
            .map_err(sqlite_error)?;
        }
        let names = relations
            .iter()
            .map(|r| r.name.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        db.authorizer(Some(move |context: AuthContext<'_>| match context.action {
            AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
            AuthAction::Read { table_name, .. }
                if names.contains(&table_name.to_ascii_lowercase()) =>
            {
                Authorization::Allow
            }
            AuthAction::Function { function_name }
                if !["load_extension", "readfile", "writefile"]
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(function_name)) =>
            {
                Authorization::Allow
            }
            _ => Authorization::Deny,
        }))
        .map_err(sqlite_error)?;
        match db.prepare(sql) {
            Ok(statement) => {
                if statement.readonly() {
                    Ok(None)
                } else {
                    Ok(Some(invalid("STATEMENT_NOT_READ_ONLY")))
                }
            }
            Err(error) => {
                let error = control.error().unwrap_or_else(|| sqlite_error(error));
                if matches!(
                    error.code,
                    ErrorCode::QuotaExceeded
                        | ErrorCode::UnavailableBackend
                        | ErrorCode::InternalFault
                ) {
                    Err(error)
                } else {
                    Ok(Some(error))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        provider::{SqlColumn, SqlFactCursor, SqlRow},
        values::{SqlType, SqlValue},
    };
    use mdd_types::{DecimalU64, ErrorCode};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Provider {
        binding: SqlBinding,
        opens: AtomicUsize,
    }
    struct Cursor {
        provider: Arc<Provider>,
        position: u32,
    }
    impl SqlFactCursor for Cursor {
        fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
            let _lease = &self.provider;
            self.position += 1;
            Ok((self.position <= 3).then(|| {
                vec![
                    SqlValue::U64(DecimalU64(u64::from(self.position))),
                    SqlValue::text("a\0b"),
                ]
            }))
        }
    }
    impl SqlFactProvider for Provider {
        fn binding(&self) -> &SqlBinding {
            &self.binding
        }
        fn relations(&self) -> MddResult<Vec<SqlRelation>> {
            Ok(vec![SqlRelation {
                name: "facts".into(),
                columns: vec![
                    SqlColumn {
                        id: "id".into(),
                        name: "id".into(),
                        data_type: SqlType::U64,
                        nullable: false,
                    },
                    SqlColumn {
                        id: "value".into(),
                        name: "value".into(),
                        data_type: SqlType::Text,
                        nullable: false,
                    },
                ],
                required_layers: vec![],
                estimated_rows: Some(DecimalU64(3)),
            }])
        }
        fn require_relation(&self, _: &str) -> MddResult<()> {
            Ok(())
        }
        fn open_cursor(
            self: Arc<Self>,
            _: &str,
            _: SqlControl,
        ) -> MddResult<Box<dyn SqlFactCursor>> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Cursor {
                provider: self,
                position: 0,
            }))
        }
    }
    fn bridge() -> (Arc<Provider>, SqlBridge) {
        let provider = Arc::new(Provider {
            binding: SqlBinding {
                provider_identity: "tiny".into(),
                snapshot_id: "tiny-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            opens: AtomicUsize::new(0),
        });
        let bridge =
            SqlBridge::new(provider.clone(), SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        (provider, bridge)
    }
    #[test]
    fn owned_cursor_is_lazy_and_preserves_multiplicity_and_nul() {
        let (provider, bridge) = bridge();
        let prepared = bridge
            .prepare("SELECT id,value FROM facts ORDER BY id")
            .unwrap();
        assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
        let output = bridge
            .execute(&prepared, SqlControl::new(SqlLimits::default(), None))
            .unwrap();
        assert_eq!(output.rows.len(), 3);
        assert_eq!(output.rows[0][1], SqlValue::text("a\0b"));
        assert!(output.profiles_admitted.is_empty());
        assert_eq!(provider.opens.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn using_join_same_carrier_retains_sqlite_merged_wildcard_shape() {
        let (_, bridge) = bridge();
        let out = bridge
            .query("SELECT * FROM facts a JOIN facts b USING(id) ORDER BY 1")
            .unwrap();
        assert_eq!(out.columns, vec!["id", "value", "value"]);
        assert_eq!(out.rows.len(), 3);
        assert!(out.rows.iter().all(|row| row.len() == 3));
        let distinct = bridge
            .query("SELECT DISTINCT * FROM facts a JOIN facts b USING(id)")
            .unwrap();
        assert_eq!(distinct.rows.len(), 3);
        assert!(distinct.rows.iter().all(|row| row.len() == 3));
        let out = bridge
            .query("SELECT a.id FROM facts a LEFT JOIN facts b USING(id) ORDER BY a.id")
            .unwrap();
        assert_eq!(out.rows.len(), 3);
        assert_eq!(
            bridge
                .query("SELECT * FROM facts a JOIN facts b USING(no_such_column)")
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    #[test]
    fn substring_retains_policy_units_and_bounded_negative_indices() {
        let (provider, native) = bridge();
        let expected = vec![
            SqlValue::text("bcd"),
            SqlValue::text("de"),
            SqlValue::text("bc"),
            SqlValue::text("\0B"),
            SqlValue::text("😀"),
            SqlValue::Null,
            SqlValue::text("B"),
            SqlValue::text("bcd"),
        ];
        let query = "SELECT substr('abcdef',2,3), substr('abcdef',-3,2), substr('abcdef',4,-2), substr('A\0B',2,2), substr('😀A',1,1), substr(NULL,1,2), substr(x'414243',2,1), substring('abcdef',2,3)";
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            assert_eq!(bridge.query(query).unwrap().rows[0], expected);
        }
        let output = native.query("SELECT substr('😀A',1,1), substr(x'414243',2,1), substr('abcdef',0,2), substr('abcdef',-9,7), substr('abcdef',9,-3), substr('abcdef',3)").unwrap();
        assert_eq!(
            output.rows[0],
            vec![
                SqlValue::Text(crate::values::SqlText {
                    utf16: vec![0xd83d],
                    original_mutf8: None
                }),
                SqlValue::Bytes(vec![b'B']),
                SqlValue::text("a"),
                SqlValue::text("abcd"),
                SqlValue::text("f"),
                SqlValue::text("cdef"),
            ]
        );
    }
    #[test]
    fn sql_authority_and_real_errors_are_not_success_or_unsupported() {
        let (_, bridge) = bridge();
        for sql in [
            "DELETE FROM facts",
            "ATTACH ':memory:' AS other",
            "PRAGMA user_version",
            "CREATE TEMP TABLE x AS SELECT 1",
            "SELECT load_extension('x')",
            "SELECT * FROM sqlite_master",
            "SELECT * FROM missing",
            "SELECT 1; SELECT 2",
            "SELECT (",
            "SELECT absent FROM facts",
        ] {
            let error = bridge.query(sql).unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidArgument, "{sql}: {error}");
        }
    }
    #[test]
    fn work_cancel_deadline_and_zero_result_budget_are_real_errors() {
        let (_, bridge) = bridge();
        let prepared = bridge.prepare("SELECT * FROM facts").unwrap();
        let cancelled = SqlControl::new(SqlLimits::default(), None);
        cancelled.cancel().unwrap();
        assert_eq!(
            bridge.execute(&prepared, cancelled).unwrap_err().code,
            ErrorCode::Cancelled
        );
        let deadline = SqlControl::new(SqlLimits::default(), Some(std::time::Instant::now()));
        assert_eq!(
            bridge.execute(&prepared, deadline).unwrap_err().code,
            ErrorCode::DeadlineExceeded
        );
        let limits = SqlLimits {
            max_result_rows: 0,
            ..SqlLimits::default()
        };
        assert_eq!(
            bridge
                .execute(&prepared, SqlControl::new(limits, None))
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    #[test]
    fn lossless_text_adapters_close_nul_surrogate_and_utf16_order_cases() {
        let (_, bridge) = bridge();
        let output=bridge.query("SELECT length('A\0B') AS n,hex(CAST('A\0B' AS BLOB)) AS h,length('😀') AS supplementary").unwrap();
        assert_eq!(
            output.rows[0],
            vec![
                SqlValue::I64(mdd_query::ir::Signed64(3)),
                SqlValue::text("410042"),
                SqlValue::I64(mdd_query::ir::Signed64(2))
            ]
        );
        let output = bridge.query("SELECT CAST(x'EDA080' AS TEXT) AS v").unwrap();
        assert_eq!(
            output.rows[0][0],
            SqlValue::Text(crate::values::SqlText {
                utf16: vec![0xd800],
                original_mutf8: None
            })
        );
        let output = bridge
            .query("SELECT '😀' AS v UNION ALL SELECT '\u{e000}' AS v ORDER BY v")
            .unwrap();
        assert_eq!(
            output.rows,
            vec![vec![SqlValue::text("😀")], vec![SqlValue::text("\u{e000}")]]
        );
    }
    #[test]
    fn like_policies_and_escaped_patterns_are_distinct() {
        let (provider, native) = bridge();
        let legacy = SqlBridge::new(provider, SqlDialect::DexSql010, SqlLimits::default()).unwrap();
        let sql = "SELECT 'axb' LIKE 'a_b' AS wildcard,'ABC' LIKE 'abc' AS ascii_case,'a_b' LIKE 'a\\_b' ESCAPE '\\' AS escaped";
        let flags = |output: SqlResult| {
            output.rows[0]
                .iter()
                .map(|v| {
                    if let SqlValue::I64(v) = v {
                        v.0
                    } else {
                        panic!("boolean callback result")
                    }
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(flags(native.query(sql).unwrap()), vec![1, 0, 1]);
        assert_eq!(flags(legacy.query(sql).unwrap()), vec![0, 1, 1]);
        let output=legacy.query("SELECT length('😀') AS n,hex(CAST('A\0B' AS TEXT)) AS h,hex(CAST('😀' AS TEXT)) AS s").unwrap();
        assert_eq!(
            output.rows[0],
            vec![
                SqlValue::I64(mdd_query::ir::Signed64(1)),
                SqlValue::text("41C08042"),
                SqlValue::text("EDA0BDEDB880")
            ]
        );
    }
    struct Unbuilt {
        inner: Arc<Provider>,
        required: AtomicUsize,
    }
    impl SqlFactProvider for Unbuilt {
        fn binding(&self) -> &SqlBinding {
            &self.inner.binding
        }
        fn relations(&self) -> MddResult<Vec<SqlRelation>> {
            self.inner.relations()
        }
        fn require_relation(&self, _: &str) -> MddResult<()> {
            self.required.fetch_add(1, Ordering::SeqCst);
            Err(mdd_types::MddError::new(
                ErrorCode::IncompleteFacts,
                "test.layer",
                "structure is unbuilt",
            ))
        }
        fn open_cursor(
            self: Arc<Self>,
            _: &str,
            _: SqlControl,
        ) -> MddResult<Box<dyn SqlFactCursor>> {
            panic!("required layer must fail before cursor")
        }
    }
    #[test]
    fn short_circuit_cannot_skip_required_layers_and_unused_cte_does_not_build_them() {
        let (provider, _) = bridge();
        let source = Arc::new(Unbuilt {
            inner: provider,
            required: AtomicUsize::new(0),
        });
        let bridge =
            SqlBridge::new(source.clone(), SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        for sql in [
            "SELECT * FROM facts LIMIT 0",
            "SELECT * FROM facts WHERE 0",
            "WITH x AS (SELECT * FROM facts) SELECT * FROM x LIMIT 0",
        ] {
            let prepared = bridge.prepare(sql).unwrap();
            assert_eq!(prepared.required_relations(), ["facts"]);
            assert_eq!(
                bridge
                    .execute(&prepared, SqlControl::new(SqlLimits::default(), None))
                    .unwrap_err()
                    .code,
                ErrorCode::IncompleteFacts
            );
        }
        let count = source.required.load(Ordering::SeqCst);
        assert_eq!(
            bridge
                .query("WITH unused AS (SELECT * FROM facts) SELECT 1 AS n")
                .unwrap()
                .rows
                .len(),
            1
        );
        assert_eq!(source.required.load(Ordering::SeqCst), count);
        assert_eq!(
            bridge.query("SELECT 1 AS n").unwrap().required_relations,
            Vec::<String>::new()
        );
    }
    struct RowsProvider {
        binding: SqlBinding,
        rows: Vec<SqlRow>,
        columns: Vec<SqlColumn>,
    }
    struct RowsCursor {
        provider: Arc<RowsProvider>,
        position: usize,
    }
    impl SqlFactCursor for RowsCursor {
        fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
            let result = self.provider.rows.get(self.position).cloned();
            self.position += 1;
            Ok(result)
        }
    }
    impl SqlFactProvider for RowsProvider {
        fn binding(&self) -> &SqlBinding {
            &self.binding
        }
        fn relations(&self) -> MddResult<Vec<SqlRelation>> {
            Ok(vec![SqlRelation {
                name: "vals".into(),
                columns: self.columns.clone(),
                required_layers: vec![],
                estimated_rows: Some(DecimalU64(self.rows.len() as u64)),
            }])
        }
        fn require_relation(&self, _: &str) -> MddResult<()> {
            Ok(())
        }
        fn open_cursor(
            self: Arc<Self>,
            _: &str,
            _: SqlControl,
        ) -> MddResult<Box<dyn SqlFactCursor>> {
            Ok(Box::new(RowsCursor {
                provider: self,
                position: 0,
            }))
        }
    }
    fn numeric_bridge() -> SqlBridge {
        let unsigned = [
            1,
            i64::MAX as u64,
            (i64::MAX as u64) + 1,
            u64::MAX,
            (1u64 << 53) + 1,
            1u64 << 53,
            0,
        ];
        let floats = [
            Some((-2.0f64).to_bits()),
            Some(f64::NEG_INFINITY.to_bits()),
            Some(0.0f64.to_bits()),
            Some((-0.0f64).to_bits()),
            Some(0x7ff8000000000042),
            Some(f64::INFINITY.to_bits()),
            None,
        ];
        let rows = unsigned
            .into_iter()
            .zip(floats)
            .map(|(u, f)| {
                vec![
                    SqlValue::U64(DecimalU64(u)),
                    f.map_or(SqlValue::Null, |bits| SqlValue::F64(DecimalU64(bits))),
                ]
            })
            .collect();
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "numeric-hand-vectors".into(),
                snapshot_id: "numeric-test-scope".into(),
                catalog_epoch: DecimalU64(0),
            },
            rows,
            columns: vec![
                SqlColumn {
                    id: "u".into(),
                    name: "u".into(),
                    data_type: SqlType::U64,
                    nullable: false,
                },
                SqlColumn {
                    id: "f".into(),
                    name: "f".into(),
                    data_type: SqlType::F64,
                    nullable: true,
                },
            ],
        });
        SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap()
    }
    #[test]
    fn native_u64_direct_case_union_and_numeric_edges_remain_lossless() {
        let bridge = numeric_bridge();
        for sql in [
            "SELECT u FROM vals ORDER BY u",
            "SELECT u FROM vals ORDER BY 1",
        ] {
            let rows = bridge.query(sql).unwrap().rows;
            let actual = rows
                .into_iter()
                .map(|row| {
                    if let SqlValue::U64(v) = row[0] {
                        v.0
                    } else {
                        panic!("U64 logical type lost")
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(
                actual,
                vec![
                    0,
                    1,
                    1u64 << 53,
                    (1u64 << 53) + 1,
                    i64::MAX as u64,
                    (i64::MAX as u64) + 1,
                    u64::MAX
                ]
            );
        }
        let rows=bridge.query("SELECT CASE WHEN u>0 THEN u ELSE CAST(0 AS UNSIGNED) END AS c FROM vals ORDER BY u").unwrap().rows;
        assert!(rows.iter().all(|row| matches!(row[0], SqlValue::U64(_))));
        let result=bridge.query("SELECT CAST(18446744073709551615 AS UNSIGNED) AS u UNION ALL SELECT CAST(1 AS UNSIGNED) AS u ORDER BY u").unwrap();
        assert_eq!(
            result.rows,
            vec![
                vec![SqlValue::U64(DecimalU64(1))],
                vec![SqlValue::U64(DecimalU64(u64::MAX))]
            ]
        );
        let result=bridge.query("SELECT u=9007199254740992.0 AS eq,u IN (9007199254740992.0) AS member FROM vals WHERE u=9007199254740993").unwrap();
        assert_eq!(
            result.rows,
            vec![vec![
                SqlValue::I64(mdd_query::ir::Signed64(0)),
                SqlValue::I64(mdd_query::ir::Signed64(0))
            ]]
        );
        let count = bridge.query("SELECT COUNT(*) AS n FROM vals").unwrap();
        assert_eq!(
            count.rows,
            vec![vec![SqlValue::I64(mdd_query::ir::Signed64(7))]]
        );
    }
    #[test]
    fn f64_sort_group_distinct_and_aggregates_do_not_use_blob_bit_order() {
        let bridge = numeric_bridge();
        let result = bridge.query("SELECT f FROM vals ORDER BY f").unwrap();
        assert_eq!(result.rows[0], vec![SqlValue::Null]);
        assert_eq!(
            result.rows[1],
            vec![SqlValue::F64(DecimalU64(f64::NEG_INFINITY.to_bits()))]
        );
        assert_eq!(
            result.rows[2],
            vec![SqlValue::F64(DecimalU64((-2.0f64).to_bits()))]
        );
        assert_eq!(
            result.rows.last().unwrap(),
            &vec![SqlValue::F64(DecimalU64(0x7ff8000000000042))]
        );
        let count = bridge
            .query("SELECT COUNT(DISTINCT f) AS n FROM vals")
            .unwrap();
        assert_eq!(
            count.rows,
            vec![vec![SqlValue::I64(mdd_query::ir::Signed64(5))]]
        );
        let rows = bridge
            .query("SELECT DISTINCT f FROM vals ORDER BY f")
            .unwrap()
            .rows;
        assert_eq!(rows.len(), 6);
        let result = bridge
            .query("SELECT MIN(f) AS lo,MAX(f) AS hi FROM vals")
            .unwrap();
        assert_eq!(
            result.rows[0],
            vec![
                SqlValue::F64(DecimalU64(f64::NEG_INFINITY.to_bits())),
                SqlValue::F64(DecimalU64(0x7ff8000000000042))
            ]
        );
    }
    #[test]
    fn blob_magic_is_never_an_internal_text_and_controls_cannot_be_rebound() {
        let (_, bridge) = bridge();
        let expected = vec![0, 77, 68, 68, 84, 69, 88, 84, 49, 0, 65];
        let rows = bridge
            .query("SELECT X'004D444454455854310041' AS b")
            .unwrap()
            .rows;
        assert_eq!(rows[0][0], SqlValue::Bytes(expected.clone()));
        let rows=bridge.query("WITH x AS (SELECT X'004D4444'||X'54455854310041' AS b) SELECT CASE WHEN 1 THEN b ELSE X'00' END AS b FROM x").unwrap().rows;
        assert_eq!(rows[0][0], SqlValue::Bytes(expected));
        let rows = bridge
            .query("SELECT 'a' LIKE 'a' ESCAPE NULL AS n")
            .unwrap()
            .rows;
        assert_eq!(rows, vec![vec![SqlValue::Null]]);
        let prepared = bridge.prepare("SELECT 1 AS n").unwrap();
        let old = SqlControl::new(SqlLimits::default(), None);
        bridge.execute(&prepared, old.clone()).unwrap();
        old.cancel().unwrap();
        assert_eq!(
            bridge.execute(&prepared, old).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        assert!(
            bridge
                .execute(&prepared, SqlControl::new(SqlLimits::default(), None))
                .is_ok()
        );
    }
}
