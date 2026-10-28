//! Immutable-provider execution with typed prepare, explicit work checkpoints and bag semantics.
use crate::ir::*;
use crate::operators::{self, Truth};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub mod facts;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct RelationSchema {
    pub columns: Schema,
    pub required_layers: Vec<FactLayer>,
}
/// Implementations must expose one immutable generation for the lifetime of their borrows.
/// The built-in catalogs own validated rows/facts; no file is reopened during execution.
pub trait FactSource {
    fn identity(&self) -> &str;
    fn snapshot_id(&self) -> &str;
    fn catalog_epoch(&self) -> DecimalU64;
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema>;
    fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()>;
    fn validate_entity(&self, entity: &mdd_facts::EntityRef) -> MddResult<()>;
    fn scan<'a>(
        &'a self,
        relation: &str,
    ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>>;
    /// None means a definition known to have no body; missing/unbuilt facts are errors.
    fn read_code_bytes(&self, entity: &mdd_facts::EntityRef) -> MddResult<Option<&[u8]>>;
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutionLimits {
    pub max_steps: u64,
    pub max_output_rows: u64,
    pub max_buffered_bytes: u64,
    pub max_cell_bytes: u64,
}
impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_steps: 1_000_000,
            max_output_rows: 100_000,
            max_buffered_bytes: 64 * 1024 * 1024,
            max_cell_bytes: 1024 * 1024,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Checkpoint {
    pub phase: &'static str,
    pub steps: DecimalU64,
    pub admitted_buffer_bytes: DecimalU64,
}
type CheckHook<'a> = dyn FnMut(&Checkpoint) -> MddResult<()> + 'a;
pub struct Control<'a> {
    limits: ExecutionLimits,
    steps: u64,
    buffered: u64,
    scanned: u64,
    hook: Option<Box<CheckHook<'a>>>,
}
impl<'a> Control<'a> {
    pub fn new(limits: ExecutionLimits) -> Self {
        Self {
            limits,
            steps: 0,
            buffered: 0,
            scanned: 0,
            hook: None,
        }
    }
    pub fn with_hook(mut self, hook: impl FnMut(&Checkpoint) -> MddResult<()> + 'a) -> Self {
        self.hook = Some(Box::new(hook));
        self
    }
    pub fn step(&mut self, phase: &'static str, amount: u64) -> MddResult<()> {
        self.steps = self
            .steps
            .checked_add(amount)
            .ok_or_else(|| quota("STEP_OVERFLOW"))?;
        if self.steps > self.limits.max_steps {
            return Err(quota("MAX_STEPS"));
        }
        if let Some(hook) = &mut self.hook {
            hook(&Checkpoint {
                phase,
                steps: DecimalU64(self.steps),
                admitted_buffer_bytes: DecimalU64(self.buffered),
            })?;
        }
        Ok(())
    }
    pub fn charge(&mut self, bytes: u64) -> MddResult<()> {
        self.buffered = self
            .buffered
            .checked_add(bytes)
            .ok_or_else(|| quota("BUFFER_OVERFLOW"))?;
        if self.buffered > self.limits.max_buffered_bytes {
            return Err(quota("MAX_BUFFERED_BYTES"));
        }
        self.step("buffer_admission", 1)
    }
    pub fn charge_cell(&mut self, bytes: u64) -> MddResult<()> {
        if bytes > self.limits.max_cell_bytes {
            return Err(quota("MAX_CELL_BYTES"));
        }
        self.charge(bytes)
    }
    pub fn charge_row(&mut self, row: &Row) -> MddResult<()> {
        self.charge(
            (std::mem::size_of::<Row>() as u64)
                .checked_add(row.len() as u64 * std::mem::size_of::<Value>() as u64)
                .ok_or_else(|| quota("ROW_SIZE_OVERFLOW"))?,
        )?;
        for cell in row {
            self.charge_cell(cell.byte_size())?;
        }
        Ok(())
    }
    fn scanned(&mut self) -> MddResult<()> {
        self.scanned = self
            .scanned
            .checked_add(1)
            .ok_or_else(|| quota("SCAN_OVERFLOW"))?;
        self.step("scan_row", 1)
    }
}
fn quota(reason: &str) -> MddError {
    MddError::new(ErrorCode::QuotaExceeded, "query.execute", reason).detail("reason", reason)
}

#[derive(Clone, Debug, Serialize)]
pub struct NodePlan {
    pub node_id: DecimalU64,
    pub operator: String,
    pub input_schemas: Vec<Schema>,
    pub output_schema: Schema,
    pub required_layers: Vec<FactLayer>,
    pub text_semantics: String,
    pub candidate_access: String,
    pub deterministic_order: bool,
}
/// Prepared plans cannot have their checked schema or required layers altered by an SDK caller.
/// ```compile_fail
/// fn forge(mut plan: mdd_query::executor::PreparedQuery) { plan.required_layers.clear(); }
/// ```
#[derive(Clone, Serialize)]
pub struct PreparedQuery {
    query: QueryIr,
    source_identity: String,
    output_schema: Schema,
    required_layers: BTreeSet<FactLayer>,
    nodes: Vec<NodePlan>,
}
impl PreparedQuery {
    pub fn schema(&self) -> &Schema {
        &self.output_schema
    }
    pub fn nodes(&self) -> &[NodePlan] {
        &self.nodes
    }
    pub fn required_layers(&self) -> &BTreeSet<FactLayer> {
        &self.required_layers
    }
    pub fn snapshot_id(&self) -> &str {
        &self.query.snapshot_id
    }
    pub fn catalog_epoch(&self) -> DecimalU64 {
        self.query.catalog_epoch
    }
}
fn expr_layers(
    expr: &Expr,
    layers: &mut BTreeSet<FactLayer>,
    source: &dyn FactSource,
    depth: usize,
) -> MddResult<()> {
    if depth > 64 {
        return Err(invalid("EXPRESSION_DEPTH_LIMIT"));
    }
    match expr {
        Expr::Column { .. } => (),
        Expr::Literal { value } => {
            value.validate(source.snapshot_id())?;
            if let Value::Entity(entity) = value {
                source.validate_entity(entity)?;
            }
            if value.byte_size() > 1024 * 1024 {
                return Err(invalid("LITERAL_CELL_LIMIT"));
            }
        }
        Expr::ReadCodeBytes {
            entity,
            byte_offset,
            byte_length,
        } => {
            if let Some(length) = byte_length {
                byte_offset
                    .0
                    .checked_add(length.0)
                    .ok_or_else(|| invalid("CODE_RANGE_OVERFLOW"))?;
            }
            if let Expr::Literal {
                value: Value::Entity(entity),
            } = entity.as_ref()
                && entity.kind != mdd_facts::EntityKind::MethodDefinition
            {
                return Err(invalid("CODE_DEFINITION_REQUIRED"));
            }
            layers.insert(FactLayer::CodeLayout);
            expr_layers(entity, layers, source, depth + 1)?;
        }
    }
    Ok(())
}
fn predicate_layers(
    p: &Predicate,
    layers: &mut BTreeSet<FactLayer>,
    source: &dyn FactSource,
    depth: usize,
) -> MddResult<()> {
    if depth > 64 {
        return Err(invalid("PREDICATE_DEPTH_LIMIT"));
    }
    match p {
        Predicate::Eq { left, right } | Predicate::RawBytesEq { left, right } => {
            expr_layers(left, layers, source, 0)?;
            expr_layers(right, layers, source, 0)?;
        }
        Predicate::Prefix { value, .. }
        | Predicate::Like { value, .. }
        | Predicate::IsNull { value } => expr_layers(value, layers, source, 0)?,
        Predicate::And { left, right } | Predicate::Or { left, right } => {
            predicate_layers(left, layers, source, depth + 1)?;
            predicate_layers(right, layers, source, depth + 1)?;
        }
        Predicate::Not { value } => predicate_layers(value, layers, source, depth + 1)?,
    }
    Ok(())
}
struct Checked {
    schema: Schema,
    layers: BTreeSet<FactLayer>,
    ordered: bool,
}
struct Preparer<'a> {
    source: &'a dyn FactSource,
    nodes: Vec<NodePlan>,
    visited: usize,
}
impl Preparer<'_> {
    fn node(&mut self, node: &Node, depth: usize) -> MddResult<Checked> {
        self.visited += 1;
        if self.visited > 1024 || depth > 64 {
            return Err(invalid("PLAN_SIZE_LIMIT"));
        }
        let mut inputs = Vec::new();
        let mut layers = BTreeSet::new();
        let mut ordered = false;
        let (schema, op, access) = match node {
            Node::Scan { relation } => {
                let s = self.source.relation_schema(relation)?;
                layers.extend(s.required_layers);
                (s.columns, "scan", "full_scan")
            }
            Node::SelectIds {
                input,
                ordinal,
                ids,
            } => {
                let s = self.node(input, depth + 1)?;
                let c = s
                    .schema
                    .get(*ordinal)
                    .ok_or_else(|| invalid("COLUMN_ORDINAL"))?;
                if !matches!(
                    c.data_type,
                    DataType::I64 | DataType::U64 | DataType::Entity
                ) {
                    return Err(invalid("ID_COLUMN_TYPE"));
                }
                if ids.len() > 4096 {
                    return Err(invalid("ID_SET_LIMIT"));
                }
                for id in ids {
                    id.validate(self.source.snapshot_id())?;
                    if let Value::Entity(entity) = id {
                        self.source.validate_entity(entity)?;
                    }
                    if id.data_type() != Some(c.data_type) {
                        return Err(invalid("ID_SET_TYPE"));
                    }
                }
                inputs.push(s.schema.clone());
                layers = s.layers;
                ordered = s.ordered;
                (s.schema, "select_ids", "full_scan_then_exact_membership")
            }
            Node::Filter { input, predicate } => {
                let s = self.node(input, depth + 1)?;
                operators::check_predicate(predicate, &s.schema, 0)?;
                layers = s.layers;
                predicate_layers(predicate, &mut layers, self.source, 0)?;
                ordered = s.ordered;
                inputs.push(s.schema.clone());
                (s.schema, "filter", "exact_predicate_no_index_omit")
            }
            Node::Project { input, columns } => {
                let s = self.node(input, depth + 1)?;
                ordered = s.ordered;
                layers = s.layers;
                let mut output = Vec::new();
                for projection in columns {
                    let (data_type, nullable) =
                        operators::expression_type(&projection.expression, &s.schema, 0)?;
                    if data_type.is_some_and(|v| v != projection.column.data_type)
                        || nullable && !projection.column.nullable
                    {
                        return Err(invalid("PROJECTION_TYPE_OR_NULLABILITY"));
                    }
                    expr_layers(&projection.expression, &mut layers, self.source, 0)?;
                    output.push(projection.column.clone());
                }
                inputs.push(s.schema);
                (output, "project", "ordinal_projection")
            }
            Node::EquiJoin {
                left,
                right,
                left_keys,
                right_keys,
                kind,
            } => {
                let a = self.node(left, depth + 1)?;
                let b = self.node(right, depth + 1)?;
                if left_keys.is_empty() || left_keys.len() != right_keys.len() {
                    return Err(invalid("JOIN_KEYS"));
                }
                for (left, right) in left_keys.iter().zip(right_keys) {
                    if a.schema
                        .get(*left)
                        .ok_or_else(|| invalid("JOIN_KEY_ORDINAL"))?
                        .data_type
                        != b.schema
                            .get(*right)
                            .ok_or_else(|| invalid("JOIN_KEY_ORDINAL"))?
                            .data_type
                    {
                        return Err(invalid("JOIN_KEY_TYPE"));
                    }
                }
                layers.extend(a.layers);
                layers.extend(b.layers);
                let mut output = a.schema.clone();
                let mut ids: BTreeSet<String> = output.iter().map(|v| v.id.clone()).collect();
                for mut column in b.schema.clone() {
                    while ids.contains(&column.id) {
                        column.id = format!("right.{}", column.id);
                    }
                    ids.insert(column.id.clone());
                    if *kind == JoinKind::Left {
                        column.nullable = true;
                    }
                    output.push(column);
                }
                inputs.extend([a.schema, b.schema]);
                (
                    output,
                    "equi_join",
                    "hash_candidates_then_exact_keys;reference_nested_loop",
                )
            }
            Node::Aggregate {
                input,
                group_by,
                aggregates,
            } => {
                let s = self.node(input, depth + 1)?;
                layers = s.layers;
                let mut output = Vec::new();
                if aggregates.is_empty() {
                    return Err(invalid("EMPTY_AGGREGATES"));
                }
                for ordinal in group_by {
                    output.push(
                        s.schema
                            .get(*ordinal)
                            .ok_or_else(|| invalid("GROUP_ORDINAL"))?
                            .clone(),
                    );
                }
                for aggregate in aggregates {
                    let t = aggregate
                        .ordinal
                        .map(|v| s.schema.get(v).ok_or_else(|| invalid("AGGREGATE_ORDINAL")))
                        .transpose()?;
                    let (data_type, nullable) = match aggregate.kind {
                        AggregateKind::CountStar => {
                            if t.is_some() {
                                return Err(invalid("COUNT_STAR_ORDINAL"));
                            }
                            (DataType::U64, false)
                        }
                        AggregateKind::Count => {
                            if t.is_none() {
                                return Err(invalid("COUNT_ORDINAL_REQUIRED"));
                            }
                            (DataType::U64, false)
                        }
                        AggregateKind::Sum => {
                            let dtype = t.ok_or_else(|| invalid("SUM_ORDINAL_REQUIRED"))?.data_type;
                            if !matches!(dtype, DataType::I64 | DataType::U64) {
                                return Err(invalid("SUM_NUMERIC_TYPE"));
                            }
                            (dtype, true)
                        }
                        AggregateKind::Min | AggregateKind::Max => (
                            t.ok_or_else(|| invalid("AGGREGATE_ORDINAL_REQUIRED"))?
                                .data_type,
                            true,
                        ),
                    };
                    if aggregate.column.data_type != data_type
                        || aggregate.column.nullable != nullable
                    {
                        return Err(invalid("AGGREGATE_OUTPUT_TYPE"));
                    }
                    output.push(aggregate.column.clone());
                }
                inputs.push(s.schema);
                (output, "aggregate", "group_bag_preserve_multiplicity")
            }
            Node::Order { input, keys } => {
                let s = self.node(input, depth + 1)?;
                if keys.is_empty() {
                    return Err(invalid("EMPTY_ORDER_KEYS"));
                }
                let mut ordinals = BTreeSet::new();
                for key in keys {
                    if key.ordinal >= s.schema.len() || !ordinals.insert(key.ordinal) {
                        return Err(invalid("ORDER_KEY_ORDINAL"));
                    }
                }
                ordered = ordinals.len() == s.schema.len();
                layers = s.layers;
                inputs.push(s.schema.clone());
                (
                    s.schema,
                    "order",
                    "controlled_stable_merge;reference_insertion",
                )
            }
            Node::Limit {
                input,
                offset,
                count,
            } => {
                offset
                    .0
                    .checked_add(count.0)
                    .ok_or_else(|| invalid("LIMIT_RANGE_OVERFLOW"))?;
                let s = self.node(input, depth + 1)?;
                ordered = s.ordered;
                layers = s.layers;
                inputs.push(s.schema.clone());
                (s.schema, "limit", "relation_limit_not_response_paging")
            }
        };
        validate_schema(&schema)?;
        self.nodes.push(NodePlan {
            node_id: DecimalU64(self.nodes.len() as u64),
            operator: op.into(),
            input_schemas: inputs,
            output_schema: schema.clone(),
            required_layers: layers.iter().copied().collect(),
            text_semantics: TEXT_VERSION.into(),
            candidate_access: access.into(),
            deterministic_order: ordered,
        });
        Ok(Checked {
            schema,
            layers,
            ordered,
        })
    }
}
pub fn prepare(query: QueryIr, source: &dyn FactSource) -> MddResult<PreparedQuery> {
    if query.schema_version != IR_VERSION || query.text_semantics != TEXT_VERSION {
        return Err(invalid("IR_OR_TEXT_VERSION"));
    }
    if query.snapshot_id != source.snapshot_id() || query.catalog_epoch != source.catalog_epoch() {
        return Err(invalid("SNAPSHOT_OR_CATALOG_GENERATION"));
    }
    let mut preparer = Preparer {
        source,
        nodes: Vec::new(),
        visited: 0,
    };
    let checked = preparer.node(&query.root, 0)?;
    if query.require_stable_order && !checked.ordered {
        return Err(invalid("TOTAL_ORDER_REQUIRED"));
    }
    source.require_layers(&checked.layers)?;
    Ok(PreparedQuery {
        query,
        source_identity: source.identity().into(),
        output_schema: checked.schema,
        required_layers: checked.layers,
        nodes: preparer.nodes,
    })
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Streaming,
    MaterializedReference,
}
/// Complete query output owns an immutable result. Delivery status belongs to the later transport.
/// ```compile_fail
/// fn forge(mut output: mdd_query::executor::QueryOutput) { output.rows.clear(); }
/// ```
#[derive(Serialize)]
pub struct QueryOutput {
    snapshot_id: String,
    catalog_epoch: DecimalU64,
    schema: Schema,
    rows: Vec<Row>,
    mode: ExecutionMode,
    execution_complete: bool,
    steps: DecimalU64,
    scanned_rows: DecimalU64,
    admitted_buffer_bytes: DecimalU64,
    ordering: &'static str,
}
impl QueryOutput {
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }
    pub fn schema(&self) -> &Schema {
        &self.schema
    }
    pub fn execution_complete(&self) -> bool {
        self.execution_complete
    }
}

enum Cursor<'a> {
    Scan {
        rows: Box<dyn Iterator<Item = MddResult<Row>> + 'a>,
        schema: Schema,
    },
    Select {
        input: Box<Cursor<'a>>,
        ordinal: usize,
        ids: BTreeSet<Value>,
    },
    Filter {
        input: Box<Cursor<'a>>,
        predicate: &'a Predicate,
    },
    Project {
        input: Box<Cursor<'a>>,
        columns: &'a [Projection],
    },
    Join {
        left: Box<Cursor<'a>>,
        right: BTreeMap<Vec<Value>, Vec<Row>>,
        left_keys: &'a [usize],
        right_width: usize,
        kind: JoinKind,
        pending: std::vec::IntoIter<Row>,
    },
    Limit {
        input: Box<Cursor<'a>>,
        offset: u64,
        remaining: u64,
    },
    Rows(std::vec::IntoIter<Row>),
}
fn key(row: &Row, ordinals: &[usize]) -> Vec<Value> {
    ordinals.iter().map(|i| row[*i].clone()).collect()
}
fn null_key(key: &[Value]) -> bool {
    key.contains(&Value::Null)
}
impl Cursor<'_> {
    fn next(
        &mut self,
        source: &dyn FactSource,
        control: &mut Control<'_>,
    ) -> MddResult<Option<Row>> {
        control.step("operator_next", 1)?;
        match self {
            Self::Scan { rows, schema } => {
                if let Some(row) = rows.next() {
                    let row = row?;
                    validate_row(&row, schema, source.snapshot_id())?;
                    control.scanned()?;
                    control.charge_row(&row)?;
                    Ok(Some(row))
                } else {
                    Ok(None)
                }
            }
            Self::Select {
                input,
                ordinal,
                ids,
            } => {
                while let Some(row) = input.next(source, control)? {
                    control.step("id_membership", 1)?;
                    if ids.contains(&row[*ordinal]) {
                        return Ok(Some(row));
                    }
                }
                Ok(None)
            }
            Self::Filter { input, predicate } => {
                while let Some(row) = input.next(source, control)? {
                    if operators::predicate(predicate, &row, source, control, false)? == Truth::True
                    {
                        return Ok(Some(row));
                    }
                }
                Ok(None)
            }
            Self::Project { input, columns } => {
                let Some(row) = input.next(source, control)? else {
                    return Ok(None);
                };
                let result = columns
                    .iter()
                    .map(|p| operators::expression(&p.expression, &row, source, control))
                    .collect::<MddResult<Row>>()?;
                control.charge_row(&result)?;
                Ok(Some(result))
            }
            Self::Limit {
                input,
                offset,
                remaining,
            } => {
                if *remaining == 0 {
                    return Ok(None);
                }
                while *offset > 0 {
                    if input.next(source, control)?.is_none() {
                        *remaining = 0;
                        return Ok(None);
                    }
                    *offset -= 1;
                }
                let row = input.next(source, control)?;
                if row.is_some() {
                    *remaining -= 1;
                }
                Ok(row)
            }
            Self::Rows(rows) => Ok(rows.next()),
            Self::Join {
                left,
                right,
                left_keys,
                right_width,
                kind,
                pending,
            } => loop {
                if let Some(row) = pending.next() {
                    return Ok(Some(row));
                }
                let Some(row) = left.next(source, control)? else {
                    return Ok(None);
                };
                let keys = key(&row, left_keys);
                let matches = if null_key(&keys) {
                    None
                } else {
                    right.get(&keys)
                };
                let mut values = Vec::new();
                if let Some(matches) = matches {
                    for r in matches {
                        control.step("join_match", 1)?;
                        let mut joined = row.clone();
                        joined.extend(r.clone());
                        control.charge_row(&joined)?;
                        values.push(joined);
                    }
                } else if *kind == JoinKind::Left {
                    let mut joined = row;
                    joined.extend(std::iter::repeat_n(Value::Null, *right_width));
                    control.charge_row(&joined)?;
                    values.push(joined);
                }
                *pending = values.into_iter();
            },
        }
    }
}
fn collect(
    cursor: &mut Cursor<'_>,
    source: &dyn FactSource,
    control: &mut Control<'_>,
) -> MddResult<Vec<Row>> {
    let mut rows = Vec::new();
    while let Some(row) = cursor.next(source, control)? {
        rows.push(row);
    }
    Ok(rows)
}

fn aggregate_values(
    rows: &[&Row],
    aggregates: &[Aggregate],
    control: &mut Control<'_>,
) -> MddResult<Row> {
    let mut output = Vec::new();
    for aggregate in aggregates {
        let mut count = 0u64;
        let mut value = Value::Null;
        for row in rows {
            control.step("aggregate_value", 1)?;
            let item = aggregate.ordinal.map(|i| &row[i]);
            match aggregate.kind {
                AggregateKind::CountStar => {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| invalid("COUNT_OVERFLOW"))?;
                }
                AggregateKind::Count => {
                    if item != Some(&Value::Null) {
                        count = count
                            .checked_add(1)
                            .ok_or_else(|| invalid("COUNT_OVERFLOW"))?;
                    }
                }
                AggregateKind::Sum => {
                    let Some(item) = item else {
                        return Err(invalid("SUM_ORDINAL_REQUIRED"));
                    };
                    if item == &Value::Null {
                        continue;
                    }
                    value = match (&value, item) {
                        (Value::Null, v) => v.clone(),
                        (Value::I64(a), Value::I64(b)) => Value::I64(Signed64(
                            a.0.checked_add(b.0)
                                .ok_or_else(|| invalid("SUM_OVERFLOW"))?,
                        )),
                        (Value::U64(a), Value::U64(b)) => Value::U64(DecimalU64(
                            a.0.checked_add(b.0)
                                .ok_or_else(|| invalid("SUM_OVERFLOW"))?,
                        )),
                        _ => return Err(invalid("SUM_NUMERIC_TYPE")),
                    };
                }
                AggregateKind::Min | AggregateKind::Max => {
                    let Some(item) = item else {
                        return Err(invalid("AGGREGATE_ORDINAL_REQUIRED"));
                    };
                    if item == &Value::Null {
                        continue;
                    }
                    if value == Value::Null
                        || (aggregate.kind == AggregateKind::Min && item < &value)
                        || (aggregate.kind == AggregateKind::Max && item > &value)
                    {
                        value = item.clone();
                    }
                }
            }
        }
        output.push(
            if matches!(
                aggregate.kind,
                AggregateKind::Count | AggregateKind::CountStar
            ) {
                Value::U64(DecimalU64(count))
            } else {
                value
            },
        );
    }
    Ok(output)
}
fn aggregate(
    rows: Vec<Row>,
    group_by: &[usize],
    aggregates: &[Aggregate],
    control: &mut Control<'_>,
    reference: bool,
) -> MddResult<Vec<Row>> {
    let mut groups: Vec<(Vec<Value>, Vec<&Row>)> = Vec::new();
    if reference {
        for row in &rows {
            let k = key(row, group_by);
            let mut index = None;
            for (at, (known, _)) in groups.iter().enumerate() {
                control.step("reference_group_compare", 1)?;
                if *known == k {
                    index = Some(at);
                    break;
                }
            }
            match index {
                Some(i) => groups[i].1.push(row),
                None => groups.push((k, vec![row])),
            }
        }
        groups.sort_by(|a, b| a.0.cmp(&b.0));
    } else {
        let mut map: BTreeMap<Vec<Value>, Vec<&Row>> = BTreeMap::new();
        for row in &rows {
            control.step("group_candidate", 1)?;
            map.entry(key(row, group_by)).or_default().push(row);
        }
        groups.extend(map);
    }
    if group_by.is_empty() && groups.is_empty() {
        groups.push((Vec::new(), Vec::new()));
    }
    let mut output = Vec::new();
    for (mut group, rows) in groups {
        group.extend(aggregate_values(&rows, aggregates, control)?);
        control.charge_row(&group)?;
        output.push(group);
    }
    Ok(output)
}
fn cursor<'a>(
    node: &'a Node,
    source: &'a dyn FactSource,
    control: &mut Control<'_>,
) -> MddResult<Cursor<'a>> {
    Ok(match node {
        Node::Scan { relation } => Cursor::Scan {
            rows: source.scan(relation)?,
            schema: source.relation_schema(relation)?.columns,
        },
        Node::SelectIds {
            input,
            ordinal,
            ids,
        } => Cursor::Select {
            input: Box::new(cursor(input, source, control)?),
            ordinal: *ordinal,
            ids: ids.iter().cloned().collect(),
        },
        Node::Filter { input, predicate } => Cursor::Filter {
            input: Box::new(cursor(input, source, control)?),
            predicate,
        },
        Node::Project { input, columns } => Cursor::Project {
            input: Box::new(cursor(input, source, control)?),
            columns,
        },
        Node::Limit {
            input,
            offset,
            count,
        } => Cursor::Limit {
            input: Box::new(cursor(input, source, control)?),
            offset: offset.0,
            remaining: count.0,
        },
        Node::Order { input, keys } => {
            let rows = collect(&mut cursor(input, source, control)?, source, control)?;
            Cursor::Rows(operators::order_rows(rows, keys, control, false)?.into_iter())
        }
        Node::Aggregate {
            input,
            group_by,
            aggregates,
        } => {
            let rows = collect(&mut cursor(input, source, control)?, source, control)?;
            Cursor::Rows(aggregate(rows, group_by, aggregates, control, false)?.into_iter())
        }
        Node::EquiJoin {
            left,
            right,
            left_keys,
            right_keys,
            kind,
        } => {
            let mut groups: BTreeMap<Vec<Value>, Vec<Row>> = BTreeMap::new();
            let mut right = cursor(right, source, control)?;
            let mut width = None;
            while let Some(row) = right.next(source, control)? {
                width = Some(row.len());
                let key = key(&row, right_keys);
                if !null_key(&key) {
                    control.charge_row(&key)?;
                    groups.entry(key).or_default().push(row);
                }
            }
            let right_width = match width {
                Some(v) => v,
                None => {
                    let mut p = Preparer {
                        source,
                        nodes: Vec::new(),
                        visited: 0,
                    };
                    p.node(
                        match node {
                            Node::EquiJoin { right, .. } => right,
                            _ => unreachable!(),
                        },
                        0,
                    )?
                    .schema
                    .len()
                }
            };
            Cursor::Join {
                left: Box::new(cursor(left, source, control)?),
                right: groups,
                left_keys,
                right_width,
                kind: *kind,
                pending: Vec::new().into_iter(),
            }
        }
    })
}
fn reference(
    node: &Node,
    source: &dyn FactSource,
    control: &mut Control<'_>,
) -> MddResult<Vec<Row>> {
    control.step("reference_node", 1)?;
    match node {
        Node::Scan { relation } => {
            let schema = source.relation_schema(relation)?.columns;
            let mut rows = Vec::new();
            for row in source.scan(relation)? {
                let row = row?;
                validate_row(&row, &schema, source.snapshot_id())?;
                control.scanned()?;
                control.charge_row(&row)?;
                rows.push(row);
            }
            Ok(rows)
        }
        Node::SelectIds {
            input,
            ordinal,
            ids,
        } => {
            let mut out = Vec::new();
            for row in reference(input, source, control)? {
                let mut found = false;
                for id in ids {
                    control.step("reference_membership", 1)?;
                    if row[*ordinal] == *id {
                        found = true;
                        break;
                    }
                }
                if found {
                    out.push(row);
                }
            }
            Ok(out)
        }
        Node::Filter { input, predicate } => {
            let mut out = Vec::new();
            for row in reference(input, source, control)? {
                if operators::predicate(predicate, &row, source, control, true)? == Truth::True {
                    out.push(row);
                }
            }
            Ok(out)
        }
        Node::Project { input, columns } => {
            let mut out = Vec::new();
            for row in reference(input, source, control)? {
                let row = columns
                    .iter()
                    .map(|p| operators::expression(&p.expression, &row, source, control))
                    .collect::<MddResult<Row>>()?;
                control.charge_row(&row)?;
                out.push(row);
            }
            Ok(out)
        }
        Node::Order { input, keys } => {
            operators::order_rows(reference(input, source, control)?, keys, control, true)
        }
        Node::Aggregate {
            input,
            group_by,
            aggregates,
        } => aggregate(
            reference(input, source, control)?,
            group_by,
            aggregates,
            control,
            true,
        ),
        Node::Limit {
            input,
            offset,
            count,
        } => {
            let rows = reference(input, source, control)?;
            Ok(rows
                .into_iter()
                .skip(usize::try_from(offset.0).unwrap_or(usize::MAX))
                .take(usize::try_from(count.0).unwrap_or(usize::MAX))
                .collect())
        }
        Node::EquiJoin {
            left,
            right,
            left_keys,
            right_keys,
            kind,
        } => {
            let left = reference(left, source, control)?;
            let right_rows = reference(right, source, control)?;
            let mut p = Preparer {
                source,
                nodes: Vec::new(),
                visited: 0,
            };
            let width = p.node(right, 0)?.schema.len();
            let mut out = Vec::new();
            for left in left {
                let mut matched = false;
                for right in &right_rows {
                    control.step("reference_join_pair", 1)?;
                    let mut equal = true;
                    for (a, b) in left_keys.iter().zip(right_keys) {
                        if left[*a] == Value::Null
                            || right[*b] == Value::Null
                            || left[*a] != right[*b]
                        {
                            equal = false;
                            break;
                        }
                    }
                    if equal {
                        matched = true;
                        let mut row = left.clone();
                        row.extend(right.clone());
                        control.charge_row(&row)?;
                        out.push(row);
                    }
                }
                if !matched && *kind == JoinKind::Left {
                    let mut row = left;
                    row.extend(std::iter::repeat_n(Value::Null, width));
                    control.charge_row(&row)?;
                    out.push(row);
                }
            }
            Ok(out)
        }
    }
}
pub fn execute(
    prepared: &PreparedQuery,
    source: &dyn FactSource,
    mode: ExecutionMode,
    control: &mut Control<'_>,
) -> MddResult<QueryOutput> {
    let bound = || {
        prepared.source_identity == source.identity()
            && prepared.query.snapshot_id == source.snapshot_id()
            && prepared.query.catalog_epoch == source.catalog_epoch()
    };
    if !bound() {
        return Err(invalid("PREPARED_SOURCE_OR_GENERATION_CHANGED"));
    }
    source.require_layers(&prepared.required_layers)?;
    control.step("execute_start", 1)?;
    let rows = match mode {
        ExecutionMode::Streaming => collect(
            &mut cursor(&prepared.query.root, source, control)?,
            source,
            control,
        )?,
        ExecutionMode::MaterializedReference => reference(&prepared.query.root, source, control)?,
    };
    if rows.len() as u64 > control.limits.max_output_rows {
        return Err(quota("MAX_OUTPUT_ROWS"));
    }
    for row in &rows {
        validate_row(row, &prepared.output_schema, source.snapshot_id())?;
        control.step("output_row", 1)?;
    }
    if !bound() {
        return Err(invalid("PREPARED_SOURCE_OR_GENERATION_CHANGED"));
    }
    control.step("execution_complete", 1)?;
    Ok(QueryOutput {
        snapshot_id: source.snapshot_id().into(),
        catalog_epoch: source.catalog_epoch(),
        schema: prepared.output_schema.clone(),
        rows,
        mode,
        execution_complete: true,
        steps: DecimalU64(control.steps),
        scanned_rows: DecimalU64(control.scanned),
        admitted_buffer_bytes: DecimalU64(control.buffered),
        ordering: if prepared.nodes.last().is_some_and(|n| n.deterministic_order) {
            "total_native_order"
        } else {
            "unspecified"
        },
    })
}
