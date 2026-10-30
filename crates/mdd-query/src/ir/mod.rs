//! Versioned typed relational IR. Native text is UTF-16; bytes are a separate lossless view.
use mdd_facts::{EntityKind, EntityRef};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::cmp::Ordering;

pub const IR_VERSION: &str = "mdd.typed-query.v1";
pub const TEXT_VERSION: &str = "mdd-text-v1";

pub fn invalid(reason: &str) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "query.ir", reason).detail("reason", reason)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Signed64(pub i64);
impl Serialize for Signed64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Signed64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let value = text.parse::<i64>().map_err(de::Error::custom)?;
        if value.to_string() != text {
            return Err(de::Error::custom("noncanonical i64 decimal"));
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Bytes(pub Vec<u8>);
impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for block in self.0.chunks(3) {
            let bits = (u32::from(block[0]) << 16)
                | (u32::from(*block.get(1).unwrap_or(&0)) << 8)
                | u32::from(*block.get(2).unwrap_or(&0));
            out.push(ALPHABET[((bits >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((bits >> 12) & 63) as usize] as char);
            out.push(if block.len() > 1 {
                ALPHABET[((bits >> 6) & 63) as usize] as char
            } else {
                '='
            });
            out.push(if block.len() > 2 {
                ALPHABET[(bits & 63) as usize] as char
            } else {
                '='
            });
        }
        serializer.serialize_str(&out)
    }
}
impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() % 4 != 0 {
            return Err(de::Error::custom("base64 length"));
        }
        let mut result = Vec::new();
        let count = text.len() / 4;
        for (index, block) in text.as_bytes().as_chunks::<4>().0.iter().enumerate() {
            let sextet = |v: u8| -> Result<u32, D::Error> {
                match v {
                    b'A'..=b'Z' => Ok(u32::from(v - b'A')),
                    b'a'..=b'z' => Ok(u32::from(v - b'a' + 26)),
                    b'0'..=b'9' => Ok(u32::from(v - b'0' + 52)),
                    b'+' => Ok(62),
                    b'/' => Ok(63),
                    _ => Err(de::Error::custom("base64 alphabet")),
                }
            };
            let a = sextet(block[0])?;
            let b = sextet(block[1])?;
            let padding = if block[2] == b'=' {
                2
            } else if block[3] == b'=' {
                1
            } else {
                0
            };
            if padding > 0 && index + 1 != count || padding == 2 && block[3] != b'=' {
                return Err(de::Error::custom("base64 padding"));
            }
            let c = if padding == 2 { 0 } else { sextet(block[2])? };
            let d = if padding > 0 { 0 } else { sextet(block[3])? };
            if padding == 2 && b & 15 != 0 || padding == 1 && c & 3 != 0 {
                return Err(de::Error::custom("base64 nonzero unused bits"));
            }
            result.push(((a << 2) | (b >> 4)) as u8);
            if padding < 2 {
                result.push(((b << 4) | (c >> 2)) as u8);
            }
            if padding == 0 {
                result.push(((c << 6) | d) as u8);
            }
        }
        Ok(Self(result))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataType {
    Bool,
    I64,
    U64,
    Utf16,
    Bytes,
    Entity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Value {
    Null,
    Bool(bool),
    I64(Signed64),
    U64(DecimalU64),
    Utf16(Vec<u16>),
    Bytes(Bytes),
    Entity(EntityRef),
}
impl Value {
    pub fn data_type(&self) -> Option<DataType> {
        Some(match self {
            Self::Null => return None,
            Self::Bool(_) => DataType::Bool,
            Self::I64(_) => DataType::I64,
            Self::U64(_) => DataType::U64,
            Self::Utf16(_) => DataType::Utf16,
            Self::Bytes(_) => DataType::Bytes,
            Self::Entity(_) => DataType::Entity,
        })
    }
    pub fn text(text: &str) -> Self {
        Self::Utf16(text.encode_utf16().collect())
    }
    pub fn byte_size(&self) -> u64 {
        match self {
            Self::Utf16(v) => v.len() as u64 * 2,
            Self::Bytes(v) => v.0.len() as u64,
            Self::Entity(v) => v.snapshot_id.len() as u64 + v.dex_occurrence_id.len() as u64 + 32,
            _ => 16,
        }
    }
    pub fn validate(&self, snapshot: &str) -> MddResult<()> {
        if let Self::Entity(v) = self
            && (v.snapshot_id != snapshot || v.dex_occurrence_id.is_empty())
        {
            return Err(invalid("ENTITY_OUTSIDE_SNAPSHOT"));
        }
        Ok(())
    }
}
fn kind(kind: EntityKind) -> u8 {
    match kind {
        EntityKind::String => 0,
        EntityKind::Type => 1,
        EntityKind::Prototype => 2,
        EntityKind::ClassDefinition => 3,
        EntityKind::FieldReference => 4,
        EntityKind::FieldDefinition => 5,
        EntityKind::MethodReference => 6,
        EntityKind::MethodDefinition => 7,
    }
}
impl Ord for Value {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Null, Self::Null) => Ordering::Equal,
            (Self::Null, _) => Ordering::Less,
            (_, Self::Null) => Ordering::Greater,
            (Self::Bool(a), Self::Bool(b)) => a.cmp(b),
            (Self::I64(a), Self::I64(b)) => a.cmp(b),
            (Self::U64(a), Self::U64(b)) => a.cmp(b),
            (Self::Utf16(a), Self::Utf16(b)) => a.cmp(b),
            (Self::Bytes(a), Self::Bytes(b)) => a.cmp(b),
            (Self::Entity(a), Self::Entity(b)) => (
                &a.snapshot_id,
                &a.dex_occurrence_id,
                kind(a.kind),
                a.local_index,
            )
                .cmp(&(
                    &b.snapshot_id,
                    &b.dex_occurrence_id,
                    kind(b.kind),
                    b.local_index,
                )),
            _ => self.data_type().cmp(&other.data_type()),
        }
    }
}
impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
pub type Row = Vec<Value>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Column {
    pub id: String,
    pub display_name: String,
    pub data_type: DataType,
    pub nullable: bool,
}
pub type Schema = Vec<Column>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactLayer {
    Metadata,
    Structure,
    Annotations,
    CodeLayout,
    References,
    Resources,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "expr", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expr {
    Column {
        ordinal: usize,
    },
    Literal {
        value: Value,
    },
    ReadCodeBytes {
        entity: Box<Expr>,
        byte_offset: DecimalU64,
        byte_length: Option<DecimalU64>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "token",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LikeToken {
    Literal(u16),
    AnyOne,
    AnyMany,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "predicate", rename_all = "snake_case", deny_unknown_fields)]
pub enum Predicate {
    Eq {
        left: Expr,
        right: Expr,
    },
    RawBytesEq {
        left: Expr,
        right: Expr,
    },
    Prefix {
        value: Expr,
        units: Vec<u16>,
    },
    Like {
        value: Expr,
        pattern: Vec<LikeToken>,
    },
    IsNull {
        value: Expr,
    },
    And {
        left: Box<Predicate>,
        right: Box<Predicate>,
    },
    Or {
        left: Box<Predicate>,
        right: Box<Predicate>,
    },
    Not {
        value: Box<Predicate>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Projection {
    pub column: Column,
    pub expression: Expr,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinKind {
    Inner,
    Left,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateKind {
    CountStar,
    Count,
    Sum,
    Min,
    Max,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aggregate {
    pub kind: AggregateKind,
    pub ordinal: Option<usize>,
    pub column: Column,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderKey {
    pub ordinal: usize,
    pub descending: bool,
    pub nulls_first: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Node {
    Scan {
        relation: String,
    },
    SelectIds {
        input: Box<Node>,
        ordinal: usize,
        ids: Vec<Value>,
    },
    Filter {
        input: Box<Node>,
        predicate: Predicate,
    },
    Project {
        input: Box<Node>,
        columns: Vec<Projection>,
    },
    EquiJoin {
        left: Box<Node>,
        right: Box<Node>,
        left_keys: Vec<usize>,
        right_keys: Vec<usize>,
        kind: JoinKind,
    },
    Aggregate {
        input: Box<Node>,
        group_by: Vec<usize>,
        aggregates: Vec<Aggregate>,
    },
    Order {
        input: Box<Node>,
        keys: Vec<OrderKey>,
    },
    Limit {
        input: Box<Node>,
        offset: DecimalU64,
        count: DecimalU64,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryIr {
    pub schema_version: String,
    pub text_semantics: String,
    pub snapshot_id: String,
    pub catalog_epoch: DecimalU64,
    pub require_stable_order: bool,
    pub root: Node,
}

pub fn validate_schema(schema: &Schema) -> MddResult<()> {
    if schema.len() > 256 {
        return Err(invalid("COLUMN_LIMIT"));
    }
    let mut ids = std::collections::BTreeSet::new();
    for column in schema {
        if column.id.is_empty() || !ids.insert(&column.id) {
            return Err(invalid("DUPLICATE_OR_EMPTY_COLUMN_ID"));
        }
    }
    Ok(())
}
pub fn validate_row(row: &Row, schema: &Schema, snapshot: &str) -> MddResult<()> {
    if row.len() != schema.len() {
        return Err(invalid("ROW_WIDTH_MISMATCH"));
    }
    for (value, column) in row.iter().zip(schema) {
        value.validate(snapshot)?;
        if value == &Value::Null {
            if !column.nullable {
                return Err(invalid("NULL_IN_NON_NULL_COLUMN"));
            }
        } else if value.data_type() != Some(column.data_type) {
            return Err(invalid("ROW_TYPE_MISMATCH"));
        }
    }
    Ok(())
}
