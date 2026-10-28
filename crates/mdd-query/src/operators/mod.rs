//! Exact native predicates and controlled comparison/sorting. No SQL or collation inference.
use crate::executor::{Control, FactSource};
use crate::ir::*;
use mdd_types::MddResult;
use std::cmp::Ordering;

/// Native UTF-16 pattern notation only, not a SQL parser/dialect admission.
/// '%' and '_' are wildcards; an explicitly selected single code unit escapes the next unit.
pub fn native_like_pattern(units: &[u16], escape: Option<u16>) -> MddResult<Vec<LikeToken>> {
    let mut tokens = Vec::new();
    let mut at = 0usize;
    while at < units.len() {
        let unit = units[at];
        at += 1;
        let token = if Some(unit) == escape {
            let escaped = *units
                .get(at)
                .ok_or_else(|| invalid("LIKE_TRAILING_ESCAPE"))?;
            at += 1;
            LikeToken::Literal(escaped)
        } else {
            match unit {
                0x25 => LikeToken::AnyMany,
                0x5f => LikeToken::AnyOne,
                v => LikeToken::Literal(v),
            }
        };
        if tokens.len() == 256 {
            return Err(invalid("LIKE_PATTERN_LIMIT"));
        }
        tokens.push(token);
    }
    Ok(tokens)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Truth {
    False,
    True,
    Unknown,
}
impl Truth {
    fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }
    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }
}

pub fn expression_type(
    expr: &Expr,
    schema: &Schema,
    depth: usize,
) -> MddResult<(Option<DataType>, bool)> {
    if depth > 64 {
        return Err(invalid("EXPRESSION_DEPTH_LIMIT"));
    }
    Ok(match expr {
        Expr::Column { ordinal } => {
            let c = schema
                .get(*ordinal)
                .ok_or_else(|| invalid("COLUMN_ORDINAL"))?;
            (Some(c.data_type), c.nullable)
        }
        Expr::Literal { value } => (value.data_type(), value == &Value::Null),
        Expr::ReadCodeBytes { entity, .. } => {
            if expression_type(entity, schema, depth + 1)?.0 != Some(DataType::Entity) {
                return Err(invalid("CODE_ENTITY_TYPE"));
            }
            (Some(DataType::Bytes), true)
        }
    })
}
fn compatible(left: Option<DataType>, right: Option<DataType>) -> bool {
    left.is_none() || right.is_none() || left == right
}
pub fn check_predicate(predicate: &Predicate, schema: &Schema, depth: usize) -> MddResult<()> {
    if depth > 64 {
        return Err(invalid("PREDICATE_DEPTH_LIMIT"));
    }
    match predicate {
        Predicate::Eq { left, right } | Predicate::RawBytesEq { left, right } => {
            let a = expression_type(left, schema, 0)?.0;
            let b = expression_type(right, schema, 0)?.0;
            if !compatible(a, b) {
                return Err(invalid("COMPARISON_TYPE_MISMATCH"));
            }
            if matches!(predicate, Predicate::RawBytesEq { .. }) {
                if a.is_some_and(|v| v != DataType::Bytes)
                    || b.is_some_and(|v| v != DataType::Bytes)
                {
                    return Err(invalid("RAW_BYTES_TYPE"));
                }
            } else if a == Some(DataType::Bytes) || b == Some(DataType::Bytes) {
                return Err(invalid("USE_RAW_BYTES_EQ"));
            }
        }
        Predicate::Prefix { value, .. } | Predicate::Like { value, .. } => {
            if expression_type(value, schema, 0)?
                .0
                .is_some_and(|v| v != DataType::Utf16)
            {
                return Err(invalid("TEXT_PREDICATE_TYPE"));
            }
            if let Predicate::Like { pattern, .. } = predicate
                && pattern.len() > 256
            {
                return Err(invalid("LIKE_PATTERN_LIMIT"));
            }
        }
        Predicate::IsNull { value } => {
            expression_type(value, schema, 0)?;
        }
        Predicate::And { left, right } | Predicate::Or { left, right } => {
            check_predicate(left, schema, depth + 1)?;
            check_predicate(right, schema, depth + 1)?;
        }
        Predicate::Not { value } => check_predicate(value, schema, depth + 1)?,
    }
    Ok(())
}
pub fn expression(
    expr: &Expr,
    row: &Row,
    source: &dyn FactSource,
    control: &mut Control<'_>,
) -> MddResult<Value> {
    control.step("expression", 1)?;
    Ok(match expr {
        Expr::Column { ordinal } => row
            .get(*ordinal)
            .ok_or_else(|| invalid("COLUMN_ORDINAL"))?
            .clone(),
        Expr::Literal { value } => {
            value.validate(source.snapshot_id())?;
            value.clone()
        }
        Expr::ReadCodeBytes {
            entity,
            byte_offset,
            byte_length,
        } => {
            let value = expression(entity, row, source, control)?;
            let Value::Entity(entity) = value else {
                if value == Value::Null {
                    return Ok(Value::Null);
                }
                return Err(invalid("CODE_ENTITY_TYPE"));
            };
            let Some(raw) = source.read_code_bytes(&entity)? else {
                return Ok(Value::Null);
            };
            let offset = usize::try_from(byte_offset.0).map_err(|_| invalid("CODE_BYTE_OFFSET"))?;
            let length = match byte_length {
                Some(v) => usize::try_from(v.0).map_err(|_| invalid("CODE_BYTE_LENGTH"))?,
                None => raw
                    .len()
                    .checked_sub(offset)
                    .ok_or_else(|| invalid("CODE_BYTE_OFFSET"))?,
            };
            let end = offset
                .checked_add(length)
                .ok_or_else(|| invalid("CODE_RANGE_OVERFLOW"))?;
            let bytes = raw
                .get(offset..end)
                .ok_or_else(|| invalid("CODE_BYTE_RANGE"))?;
            control.charge_cell(bytes.len() as u64)?;
            Value::Bytes(Bytes(bytes.to_vec()))
        }
    })
}
fn equality(left: Value, right: Value) -> Truth {
    if left == Value::Null || right == Value::Null {
        Truth::Unknown
    } else if left == right {
        Truth::True
    } else {
        Truth::False
    }
}
fn like_dp(text: &[u16], pattern: &[LikeToken], control: &mut Control<'_>) -> MddResult<bool> {
    control.charge((text.len() as u64 + 1) * 2)?;
    let mut previous = vec![false; text.len() + 1];
    previous[0] = true;
    for token in pattern {
        let mut next = vec![false; text.len() + 1];
        for at in 0..=text.len() {
            control.step("like_cell", 1)?;
            next[at] = match token {
                LikeToken::AnyMany => previous[at] || (at > 0 && next[at - 1]),
                LikeToken::AnyOne => at > 0 && previous[at - 1],
                LikeToken::Literal(unit) => at > 0 && previous[at - 1] && text[at - 1] == *unit,
            };
        }
        previous = next;
    }
    Ok(previous[text.len()])
}
fn like_reference(
    text: &[u16],
    pattern: &[LikeToken],
    control: &mut Control<'_>,
) -> MddResult<bool> {
    control.step("reference_like", 1)?;
    let Some((token, rest)) = pattern.split_first() else {
        return Ok(text.is_empty());
    };
    match token {
        LikeToken::AnyMany => {
            for start in 0..=text.len() {
                if like_reference(&text[start..], rest, control)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        LikeToken::AnyOne => {
            if text.is_empty() {
                Ok(false)
            } else {
                like_reference(&text[1..], rest, control)
            }
        }
        LikeToken::Literal(unit) => {
            if text.first() != Some(unit) {
                Ok(false)
            } else {
                like_reference(&text[1..], rest, control)
            }
        }
    }
}

pub fn predicate(
    predicate: &Predicate,
    row: &Row,
    source: &dyn FactSource,
    control: &mut Control<'_>,
    reference: bool,
) -> MddResult<Truth> {
    control.step("predicate", 1)?;
    Ok(match predicate {
        Predicate::Eq { left, right } | Predicate::RawBytesEq { left, right } => equality(
            expression(left, row, source, control)?,
            expression(right, row, source, control)?,
        ),
        Predicate::Prefix { value, units } => match expression(value, row, source, control)? {
            Value::Null => Truth::Unknown,
            Value::Utf16(v) => {
                if v.starts_with(units) {
                    Truth::True
                } else {
                    Truth::False
                }
            }
            _ => return Err(invalid("TEXT_PREDICATE_TYPE")),
        },
        Predicate::Like { value, pattern } => match expression(value, row, source, control)? {
            Value::Null => Truth::Unknown,
            Value::Utf16(v) => {
                let yes = if reference {
                    like_reference(&v, pattern, control)?
                } else {
                    like_dp(&v, pattern, control)?
                };
                if yes { Truth::True } else { Truth::False }
            }
            _ => return Err(invalid("TEXT_PREDICATE_TYPE")),
        },
        Predicate::IsNull { value } => {
            if expression(value, row, source, control)? == Value::Null {
                Truth::True
            } else {
                Truth::False
            }
        }
        Predicate::And { left, right } => predicate_eval(left, row, source, control, reference)?
            .and(predicate_eval(right, row, source, control, reference)?),
        Predicate::Or { left, right } => predicate_eval(left, row, source, control, reference)?
            .or(predicate_eval(right, row, source, control, reference)?),
        Predicate::Not { value } => predicate_eval(value, row, source, control, reference)?.not(),
    })
}
fn predicate_eval(
    p: &Predicate,
    r: &Row,
    s: &dyn FactSource,
    c: &mut Control<'_>,
    reference: bool,
) -> MddResult<Truth> {
    predicate(p, r, s, c, reference)
}

pub fn compare_rows(left: &Row, right: &Row, keys: &[OrderKey]) -> Ordering {
    for key in keys {
        let (a, b) = (&left[key.ordinal], &right[key.ordinal]);
        let order = match (a, b) {
            (Value::Null, Value::Null) => Ordering::Equal,
            (Value::Null, _) => {
                if key.nulls_first {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            (_, Value::Null) => {
                if key.nulls_first {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            _ => {
                if key.descending {
                    b.cmp(a)
                } else {
                    a.cmp(b)
                }
            }
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    Ordering::Equal
}
pub fn order_rows(
    rows: Vec<Row>,
    keys: &[OrderKey],
    control: &mut Control<'_>,
    reference: bool,
) -> MddResult<Vec<Row>> {
    control.charge(rows.len() as u64 * 16)?;
    let mut indices: Vec<usize> = (0..rows.len()).collect();
    if reference {
        for at in 1..indices.len() {
            let mut position = at;
            while position > 0 {
                control.step("reference_sort_compare", 1)?;
                if compare_rows(&rows[indices[position - 1]], &rows[indices[position]], keys)
                    != Ordering::Greater
                {
                    break;
                }
                indices.swap(position - 1, position);
                position -= 1;
            }
        }
    } else {
        let mut width = 1usize;
        let mut scratch = vec![0; indices.len()];
        while width < indices.len() {
            for start in (0..indices.len()).step_by(width.saturating_mul(2)) {
                let mid = (start + width).min(indices.len());
                let end = mid.saturating_add(width).min(indices.len());
                let (mut a, mut b) = (start, mid);
                for item in &mut scratch[start..end] {
                    control.step("sort_compare", 1)?;
                    if b == end
                        || (a < mid
                            && compare_rows(&rows[indices[a]], &rows[indices[b]], keys)
                                != Ordering::Greater)
                    {
                        *item = indices[a];
                        a += 1;
                    } else {
                        *item = indices[b];
                        b += 1;
                    }
                }
            }
            std::mem::swap(&mut scratch, &mut indices);
            width = width
                .checked_mul(2)
                .ok_or_else(|| invalid("SORT_WIDTH_OVERFLOW"))?;
        }
    }
    indices
        .into_iter()
        .map(|index| {
            control.charge_row(&rows[index])?;
            Ok(rows[index].clone())
        })
        .collect()
}
