use crate::control::SqlControl;
use crate::{
    invalid,
    values::{SqlType, SqlValue},
};
use mdd_query::ir::FactLayer;
use mdd_types::{DecimalU64, MddResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
pub mod metadata;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqlBinding {
    pub provider_identity: String,
    pub snapshot_id: String,
    pub catalog_epoch: DecimalU64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqlColumn {
    pub id: String,
    pub name: String,
    pub data_type: SqlType,
    pub nullable: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SqlRelation {
    pub name: String,
    pub columns: Vec<SqlColumn>,
    pub required_layers: Vec<FactLayer>,
    pub estimated_rows: Option<DecimalU64>,
}
pub type SqlRow = Vec<SqlValue>;

/// Provider owns one immutable source generation. Opening a cursor may build
/// required facts, but schema/optimizer callbacks must never do so.
pub trait SqlFactProvider: Send + Sync {
    fn binding(&self) -> &SqlBinding;
    fn relations(&self) -> MddResult<Vec<SqlRelation>>;
    fn require_relation(&self, relation: &str) -> MddResult<()>;
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>>;
}
/// Own the Arc and ordinal/iterator state. No self-referential borrowed scan.
pub trait SqlFactCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>>;
}

pub(crate) fn validate_row(row: &SqlRow, columns: &[SqlColumn]) -> MddResult<()> {
    if row.len() != columns.len() {
        return Err(invalid("PROVIDER_ROW_WIDTH"));
    }
    for (value, column) in row.iter().zip(columns) {
        if value == &SqlValue::Null {
            if !column.nullable {
                return Err(invalid("PROVIDER_UNEXPECTED_NULL"));
            }
        } else if value.data_type() != Some(column.data_type) {
            return Err(invalid("PROVIDER_ROW_TYPE"));
        }
    }
    Ok(())
}
