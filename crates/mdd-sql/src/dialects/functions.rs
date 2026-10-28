use crate::{
    control::SqlControl,
    dialects::SqlDialect,
    invalid, quota,
    values::{SqlText, SqlValue},
};
use mdd_query::ir::Signed64;
use mdd_types::{DecimalU64, MddError, MddResult};
use rusqlite::{
    Connection,
    functions::{Aggregate, Context, FunctionFlags},
    types::Value as Cell,
};
use std::cmp::Ordering;

fn integer(value: &SqlValue) -> MddResult<i128> {
    match value {
        SqlValue::I64(v) => Ok(i128::from(v.0)),
        SqlValue::U64(v) => Ok(i128::from(v.0)),
        SqlValue::Bool(v) => Ok(i128::from(*v)),
        _ => Err(invalid("INTEGER_VALUE_REQUIRED")),
    }
}
fn integer_value(value: i128, unsigned: bool) -> MddResult<SqlValue> {
    if unsigned && value >= 0 {
        return u64::try_from(value)
            .map(|v| SqlValue::U64(DecimalU64(v)))
            .map_err(|_| invalid("INTEGER_OVERFLOW"));
    }
    if let Ok(value) = i64::try_from(value) {
        Ok(SqlValue::I64(Signed64(value)))
    } else if let Ok(value) = u64::try_from(value) {
        Ok(SqlValue::U64(DecimalU64(value)))
    } else {
        Err(invalid("INTEGER_OVERFLOW"))
    }
}
fn scalar_text(value: &SqlValue) -> MddResult<SqlText> {
    Ok(match value {
        SqlValue::Text(value) => value.clone(),
        SqlValue::I64(v) => SqlText::from_utf8(&v.0.to_string()),
        SqlValue::U64(v) => SqlText::from_utf8(&v.0.to_string()),
        SqlValue::Bool(v) => SqlText::from_utf8(if *v { "1" } else { "0" }),
        SqlValue::F64(bits) => SqlText::from_utf8(&f64::from_bits(bits.0).to_string()),
        SqlValue::DexMutf8 { bytes, .. } => decoded_text(bytes, SqlDialect::DexSql010)?,
        _ => return Err(invalid("TEXT_CONVERSION_TYPE")),
    })
}
fn encoded_text(text: &SqlText, dialect: SqlDialect) -> Vec<u8> {
    fn emit(code: u32, out: &mut Vec<u8>) {
        if code < 0x80 {
            out.push(code as u8);
        } else if code < 0x800 {
            out.extend([(0xc0 | (code >> 6)) as u8, (0x80 | (code & 63)) as u8]);
        } else if code < 0x10000 {
            out.extend([
                (0xe0 | (code >> 12)) as u8,
                (0x80 | ((code >> 6) & 63)) as u8,
                (0x80 | (code & 63)) as u8,
            ]);
        } else {
            out.extend([
                (0xf0 | (code >> 18)) as u8,
                (0x80 | ((code >> 12) & 63)) as u8,
                (0x80 | ((code >> 6) & 63)) as u8,
                (0x80 | (code & 63)) as u8,
            ]);
        }
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at < text.utf16.len() {
        let value = text.utf16[at];
        if dialect != SqlDialect::NativeV1 && value == 0 {
            out.extend([0xc0, 0x80]);
        } else if dialect == SqlDialect::NativeV1
            && (0xd800..=0xdbff).contains(&value)
            && text
                .utf16
                .get(at + 1)
                .is_some_and(|v| (0xdc00..=0xdfff).contains(v))
        {
            let low = text.utf16[at + 1];
            emit(
                0x10000 + ((u32::from(value) - 0xd800) << 10) + (u32::from(low) - 0xdc00),
                &mut out,
            );
            at += 1;
        } else {
            emit(u32::from(value), &mut out);
        }
        at += 1;
    }
    out
}
fn decoded_text(bytes: &[u8], dialect: SqlDialect) -> MddResult<SqlText> {
    let mut units = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let first = bytes[at];
        let (count, mut value, min) = match first {
            0..=0x7f => (1, u32::from(first), 0),
            0xc0..=0xdf => (2, u32::from(first & 31), 0x80),
            0xe0..=0xef => (3, u32::from(first & 15), 0x800),
            0xf0..=0xf4 => (4, u32::from(first & 7), 0x10000),
            _ => return Err(invalid("CAST_TEXT_BAD_ENCODING")),
        };
        if at + count > bytes.len() {
            return Err(invalid("CAST_TEXT_TRUNCATED_ENCODING"));
        }
        for byte in &bytes[at + 1..at + count] {
            if byte & 0xc0 != 0x80 {
                return Err(invalid("CAST_TEXT_BAD_CONTINUATION"));
            }
            value = (value << 6) | u32::from(byte & 63);
        }
        if value < min
            && !(dialect != SqlDialect::NativeV1 && count == 2 && value == 0 && first == 0xc0)
        {
            return Err(invalid("CAST_TEXT_OVERLONG_ENCODING"));
        }
        if value > 0x10ffff {
            return Err(invalid("CAST_TEXT_CODEPOINT_RANGE"));
        }
        if value >= 0x10000 {
            let value = value - 0x10000;
            units.extend([
                0xd800 | (value >> 10) as u16,
                0xdc00 | (value & 1023) as u16,
            ]);
        } else {
            units.push(value as u16);
        }
        at += count;
    }
    Ok(SqlText {
        utf16: units,
        original_mutf8: None,
    })
}
fn int_float_cmp(integer: i128, float: f64) -> Ordering {
    if float.is_nan() {
        return Ordering::Less;
    }
    if float == f64::INFINITY {
        return Ordering::Less;
    }
    if float == f64::NEG_INFINITY {
        return Ordering::Greater;
    }
    if integer < 0 && float >= 0.0 {
        return Ordering::Less;
    }
    if integer >= 0 && float < 0.0 {
        return Ordering::Greater;
    }
    let negative = integer < 0;
    let magnitude = integer.unsigned_abs();
    let value = float.abs();
    let order = if value >= 18446744073709551616.0 {
        Ordering::Less
    } else {
        let floor = value as u64;
        match magnitude.cmp(&u128::from(floor)) {
            Ordering::Equal if value.fract() != 0.0 => Ordering::Less,
            order => order,
        }
    };
    if negative { order.reverse() } else { order }
}
fn compare(left: &SqlValue, right: &SqlValue) -> MddResult<Ordering> {
    if storage_class(left) != storage_class(right) {
        return Err(MddError::new(
            mdd_types::ErrorCode::UnsupportedQuery,
            "sql.affinity",
            "MIXED_CLASS_AFFINITY_NOT_IMPLEMENTED",
        ));
    }
    if let (Some(left), Some(right)) = (left.bytes(), right.bytes()) {
        return Ok(left.cmp(right));
    }
    Ok(match (left, right) {
        (SqlValue::Text(a), SqlValue::Text(b)) => a.utf16.cmp(&b.utf16),
        (SqlValue::Bytes(a), SqlValue::Bytes(b)) => a.cmp(b),
        (SqlValue::F64(a), SqlValue::F64(b)) => {
            let (x, y) = (f64::from_bits(a.0), f64::from_bits(b.0));
            if x.is_nan() && y.is_nan() {
                a.0.cmp(&b.0)
            } else if x.is_nan() {
                Ordering::Greater
            } else if y.is_nan() {
                Ordering::Less
            } else {
                x.partial_cmp(&y).unwrap()
            }
        }
        (SqlValue::F64(a), b) => int_float_cmp(integer(b)?, f64::from_bits(a.0)).reverse(),
        (a, SqlValue::F64(b)) => int_float_cmp(integer(a)?, f64::from_bits(b.0)),
        (a, b) => integer(a)?.cmp(&integer(b)?),
    })
}
fn storage_class(value: &SqlValue) -> u8 {
    match value {
        SqlValue::Null => 0,
        SqlValue::Bool(_) | SqlValue::I64(_) | SqlValue::U64(_) | SqlValue::F64(_) => 1,
        SqlValue::Text(_) => 2,
        SqlValue::Bytes(_) | SqlValue::DexMutf8 { .. } => 3,
    }
}
fn compare_literal(left: &SqlValue, right: &SqlValue) -> MddResult<Ordering> {
    let order = storage_class(left).cmp(&storage_class(right));
    if order == Ordering::Equal {
        compare(left, right)
    } else {
        Ok(order)
    }
}
fn equality_key(value: &SqlValue) -> MddResult<Vec<u8>> {
    // Canonical mathematical numeric keys: u64/i64 boundaries and exactly
    // represented float integers compare equally. IEEE payloads remain on the
    // value carrier; signed zero has one SQL equality/sort key.
    let mut out = b"\0MDDKEY1".to_vec();
    match value {
        SqlValue::Text(text) => {
            out.push(1);
            for unit in &text.utf16 {
                out.extend(unit.to_be_bytes());
            }
        }
        SqlValue::Bytes(bytes) | SqlValue::DexMutf8 { bytes, .. } => {
            out.push(2);
            out.extend(bytes);
        }
        value => {
            out.push(0);
            let (negative, exponent, significand, special) = match value {
                SqlValue::F64(bits) => {
                    let number = f64::from_bits(bits.0);
                    let sign = bits.0 >> 63 != 0;
                    let exponent = ((bits.0 >> 52) & 2047) as i32;
                    let fraction = bits.0 & ((1u64 << 52) - 1);
                    if number.is_nan() {
                        out.push(5);
                        out.extend(bits.0.to_be_bytes());
                        return Ok(out);
                    }
                    if number.is_infinite() {
                        (sign, 0, 0, if sign { 0 } else { 4 })
                    } else if number == 0.0 {
                        (false, 0, 0, 2)
                    } else if exponent == 0 {
                        let bit = 63 - fraction.leading_zeros();
                        (
                            sign,
                            bit as i32 - 1074,
                            fraction << (63 - bit),
                            if sign { 1 } else { 3 },
                        )
                    } else {
                        (
                            sign,
                            exponent - 1023,
                            ((1u64 << 52) | fraction) << 11,
                            if sign { 1 } else { 3 },
                        )
                    }
                }
                value => {
                    let integer = integer(value)?;
                    let magnitude = integer.unsigned_abs() as u64;
                    if magnitude == 0 {
                        (false, 0, 0, 2)
                    } else {
                        let exponent = 63 - magnitude.leading_zeros();
                        (
                            integer < 0,
                            exponent as i32,
                            magnitude << (63 - exponent),
                            if integer < 0 { 1 } else { 3 },
                        )
                    }
                }
            };
            out.push(special);
            if special == 1 || special == 3 {
                let encoded = (exponent + 2048) as u16;
                let mut payload = encoded
                    .to_be_bytes()
                    .into_iter()
                    .chain(significand.to_be_bytes())
                    .collect::<Vec<_>>();
                if negative {
                    for byte in &mut payload {
                        *byte = !*byte;
                    }
                }
                out.extend(payload);
            }
        }
    }
    Ok(out)
}
fn numeric(left: &SqlValue, right: &SqlValue, operation: &str) -> MddResult<SqlValue> {
    if matches!(left, SqlValue::Null) || matches!(right, SqlValue::Null) {
        return Ok(SqlValue::Null);
    }
    if matches!(left, SqlValue::F64(_)) || matches!(right, SqlValue::F64(_)) {
        let float = |value: &SqlValue| -> MddResult<f64> {
            if let SqlValue::F64(bits) = value {
                Ok(f64::from_bits(bits.0))
            } else {
                let number = integer(value)?;
                if number.unsigned_abs() > (1u128 << 53) {
                    return Err(invalid("INEXACT_INTEGER_FLOAT_COERCION"));
                }
                Ok(number as f64)
            }
        };
        let (a, b) = (float(left)?, float(right)?);
        if b == 0.0 && matches!(operation, "div" | "mod") {
            return Ok(SqlValue::Null);
        }
        return Ok(SqlValue::F64(DecimalU64(
            match operation {
                "add" => a + b,
                "sub" => a - b,
                "mul" => a * b,
                "div" => a / b,
                "mod" => a % b,
                _ => return Err(invalid("NUMERIC_OPERATION")),
            }
            .to_bits(),
        )));
    }
    let (a, b) = (integer(left)?, integer(right)?);
    if b == 0 && matches!(operation, "div" | "mod") {
        return Ok(SqlValue::Null);
    }
    let value = match operation {
        "add" => a.checked_add(b),
        "sub" => a.checked_sub(b),
        "mul" => a.checked_mul(b),
        "div" => a.checked_div(b),
        "mod" => a.checked_rem(b),
        _ => return Err(invalid("NUMERIC_OPERATION")),
    }
    .ok_or_else(|| invalid("INTEGER_OVERFLOW"))?;
    integer_value(
        value,
        matches!(left, SqlValue::U64(_)) || matches!(right, SqlValue::U64(_)),
    )
}
/// SQLite's integer CAST consumes an ASCII decimal prefix and saturates at
/// signed 64-bit bounds. Inspect units directly: no surrogate replacement or
/// UTF-8 display conversion can enter this numeric operation.
fn sqlite_integer_prefix(units: impl Iterator<Item = u16>, control: &SqlControl) -> MddResult<i64> {
    let mut units = units.peekable();
    let mut consumed = 0usize;
    let mut tick = || -> MddResult<()> {
        consumed += 1;
        if consumed.is_multiple_of(128) {
            control.checkpoint(1, false)?;
        }
        Ok(())
    };
    while units
        .peek()
        .is_some_and(|unit| matches!(*unit, 9..=13 | 32))
    {
        units.next();
        tick()?;
    }
    let negative = match units.peek() {
        Some(45) => {
            units.next();
            tick()?;
            true
        }
        Some(43) => {
            units.next();
            tick()?;
            false
        }
        _ => false,
    };
    let limit = (i64::MAX as u64) + u64::from(negative);
    let mut magnitude = 0u64;
    while let Some(unit @ 48..=57) = units.peek().copied() {
        units.next();
        tick()?;
        let digit = u64::from(unit - 48);
        if magnitude > (limit - digit) / 10 {
            return Ok(if negative { i64::MIN } else { i64::MAX });
        }
        magnitude = magnitude * 10 + digit;
    }
    Ok(if negative && magnitude == (i64::MAX as u64) + 1 {
        i64::MIN
    } else if negative {
        -(magnitude as i64)
    } else {
        magnitude as i64
    })
}
fn cast(
    value: SqlValue,
    target: &str,
    dialect: SqlDialect,
    control: &SqlControl,
) -> MddResult<SqlValue> {
    if value == SqlValue::Null {
        return Ok(value);
    }
    if target == "i64" && dialect != SqlDialect::NativeV1 {
        let parsed = match &value {
            SqlValue::Text(text) => {
                Some(sqlite_integer_prefix(text.utf16.iter().copied(), control)?)
            }
            SqlValue::Bytes(bytes) | SqlValue::DexMutf8 { bytes, .. } => Some(
                sqlite_integer_prefix(bytes.iter().copied().map(u16::from), control)?,
            ),
            _ => None,
        };
        if let Some(parsed) = parsed {
            return Ok(SqlValue::I64(Signed64(parsed)));
        }
    }
    Ok(match target {
        "text" => SqlValue::Text(if let SqlValue::Bytes(bytes) = value {
            decoded_text(&bytes, dialect)?
        } else if let SqlValue::F64(bits) = value {
            let number = f64::from_bits(bits.0);
            let text = if dialect == SqlDialect::NativeV1 {
                format!("{number:?}")
            } else {
                legacy_float_text(number)?
            };
            SqlText::from_utf8(&text)
        } else {
            scalar_text(&value)?
        }),
        "bytes" => match value {
            SqlValue::Bytes(_) => value,
            SqlValue::DexMutf8 { bytes, .. } => SqlValue::Bytes(bytes),
            value => SqlValue::Bytes(encoded_text(&scalar_text(&value)?, dialect)),
        },
        "i64" => {
            let value = if let SqlValue::Text(text) = &value {
                text.strict_utf8()?
                    .parse::<i128>()
                    .map_err(|_| invalid("INVALID_INTEGER_CAST"))?
            } else {
                integer(&value)?
            };
            SqlValue::I64(Signed64(
                i64::try_from(value).map_err(|_| invalid("INTEGER_CAST_OVERFLOW"))?,
            ))
        }
        "u64" => {
            let value = if let SqlValue::Text(text) = &value {
                text.strict_utf8()?
                    .parse::<i128>()
                    .map_err(|_| invalid("INVALID_UNSIGNED_CAST"))?
            } else {
                integer(&value)?
            };
            SqlValue::U64(DecimalU64(
                u64::try_from(value).map_err(|_| invalid("UNSIGNED_CAST_OVERFLOW"))?,
            ))
        }
        "f64" => {
            let value = if let SqlValue::F64(_) = value {
                return Ok(value);
            } else if let SqlValue::Text(text) = &value {
                text.strict_utf8()?
                    .parse::<f64>()
                    .map_err(|_| invalid("INVALID_FLOAT_CAST"))?
            } else {
                let n = integer(&value)?;
                if n.unsigned_abs() > (1u128 << 53) {
                    return Err(invalid("INEXACT_FLOAT_CAST"));
                }
                n as f64
            };
            SqlValue::F64(DecimalU64(value.to_bits()))
        }
        "bool" => SqlValue::Bool(integer(&value)? != 0),
        _ => return Err(invalid("UNKNOWN_CAST_TARGET")),
    })
}
fn legacy_float_text(value: f64) -> MddResult<String> {
    let value = if value == 0.0 { 0.0 } else { value };
    let mut buffer = [0u8; 128];
    // SAFETY: the fixed format requires exactly one promoted C double. The
    // buffer pointer/length agree; sqlite3_snprintf always NUL terminates for
    // positive capacity. No connection or source pointer crosses this call.
    unsafe {
        rusqlite::ffi::sqlite3_snprintf(
            buffer.len() as i32,
            buffer.as_mut_ptr().cast(),
            c"%!.15g".as_ptr(),
            value,
        );
    }
    let end = buffer.iter().position(|b| *b == 0).ok_or_else(|| {
        MddError::new(
            mdd_types::ErrorCode::InternalFault,
            "sql.cast",
            "SQLite float formatter did not terminate",
        )
    })?;
    std::str::from_utf8(&buffer[..end])
        .map(str::to_owned)
        .map_err(|_| {
            MddError::new(
                mdd_types::ErrorCode::InternalFault,
                "sql.cast",
                "SQLite float formatter emitted non UTF8",
            )
        })
}
fn like(
    value: &SqlText,
    pattern: &SqlText,
    escape: Option<u16>,
    dialect: SqlDialect,
    control: &SqlControl,
) -> MddResult<bool> {
    #[derive(Clone, Copy)]
    enum Token {
        Literal(u16),
        One,
        Many,
    }
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < pattern.utf16.len() {
        let unit = pattern.utf16[at];
        if Some(unit) == escape {
            at += 1;
            tokens.push(Token::Literal(
                *pattern
                    .utf16
                    .get(at)
                    .ok_or_else(|| invalid("LIKE_DANGLING_ESCAPE"))?,
            ));
        } else if unit == 37 {
            tokens.push(Token::Many);
        } else if unit == 95 && dialect == SqlDialect::NativeV1 {
            tokens.push(Token::One);
        } else {
            tokens.push(Token::Literal(unit));
        }
        at += 1;
    }
    let fold = |v: u16| {
        if dialect != SqlDialect::NativeV1 && (65..=90).contains(&v) {
            v + 32
        } else {
            v
        }
    };
    let (mut input, mut token, mut star, mut restart) = (0usize, 0usize, None, 0usize);
    while input < value.utf16.len() {
        control.checkpoint(1, false)?;
        if token < tokens.len()
            && match tokens[token] {
                Token::One => true,
                Token::Literal(v) => fold(v) == fold(value.utf16[input]),
                Token::Many => false,
            }
        {
            input += 1;
            token += 1;
        } else if token < tokens.len() && matches!(tokens[token], Token::Many) {
            star = Some(token);
            token += 1;
            restart = input;
        } else if let Some(star) = star {
            restart += 1;
            input = restart;
            token = star + 1;
        } else {
            return Ok(false);
        }
    }
    while token < tokens.len() && matches!(tokens[token], Token::Many) {
        token += 1;
    }
    Ok(token == tokens.len())
}
fn substring_range(length: usize, start: i128, count: Option<i128>) -> (usize, usize) {
    let len = length as i128;
    let offset = if start > 0 {
        start - 1
    } else if start < 0 {
        len + start
    } else {
        0
    };
    let count = count.unwrap_or(i128::from(i64::MAX));
    let (begin, end) = if count < 0 {
        (offset + count, offset)
    } else {
        (offset, offset + count - i128::from(start == 0 && count > 0))
    };
    (begin.clamp(0, len) as usize, end.clamp(0, len) as usize)
}
fn scalar(
    name: &str,
    args: &[SqlValue],
    dialect: SqlDialect,
    control: &SqlControl,
) -> MddResult<SqlValue> {
    control.checkpoint(1, false)?;
    if name == "mdd_hex" {
        let bytes = match &args[0] {
            SqlValue::Null => Vec::new(),
            SqlValue::Bytes(bytes) | SqlValue::DexMutf8 { bytes, .. } => bytes.clone(),
            value => encoded_text(&scalar_text(value)?, dialect),
        };
        if bytes.len() as u64 > control.inner.limits.max_cell_bytes / 4 {
            return Err(quota("HEX_RESULT_CELL_BYTES"));
        }
        return Ok(SqlValue::text(
            &bytes.iter().map(|b| format!("{b:02X}")).collect::<String>(),
        ));
    }
    if name == "mdd_key" || name == "mdd_sort_key" {
        if args[0] == SqlValue::Null {
            return Ok(SqlValue::Null);
        }
        return Ok(SqlValue::Bytes(equality_key(&args[0])?));
    }
    if name == "mdd_nullif" {
        if args[0] == SqlValue::Null {
            return Ok(SqlValue::Null);
        }
        if args[1] != SqlValue::Null && compare(&args[0], &args[1])? == Ordering::Equal {
            return Ok(SqlValue::Null);
        }
        return Ok(args[0].clone());
    }
    if args
        .iter()
        .take(if name == "mdd_like" { 2 } else { args.len() })
        .any(|value| value == &SqlValue::Null)
    {
        return Ok(SqlValue::Null);
    }
    match name {
        "mdd_substr" => {
            let start = integer(&args[1])?;
            let count = args.get(2).map(integer).transpose()?;
            if dialect == SqlDialect::NativeV1
                && let SqlValue::Bytes(bytes) = &args[0]
            {
                let (begin, end) = substring_range(bytes.len(), start, count);
                return Ok(SqlValue::Bytes(bytes[begin..end].to_vec()));
            }
            let text = match &args[0] {
                SqlValue::Bytes(bytes) => decoded_text(bytes, dialect)?,
                value => scalar_text(value)?,
            };
            let mut offsets = Vec::with_capacity(text.utf16.len() + 1);
            let mut at = 0;
            while at < text.utf16.len() {
                offsets.push(at);
                if dialect != SqlDialect::NativeV1
                    && (0xd800..=0xdbff).contains(&text.utf16[at])
                    && text
                        .utf16
                        .get(at + 1)
                        .is_some_and(|v| (0xdc00..=0xdfff).contains(v))
                {
                    at += 2;
                } else {
                    at += 1;
                }
            }
            offsets.push(at);
            let (begin, end) = substring_range(offsets.len() - 1, start, count);
            Ok(SqlValue::Text(SqlText {
                utf16: text.utf16[offsets[begin]..offsets[end]].to_vec(),
                original_mutf8: None,
            }))
        }
        "mdd_length" => {
            let text = scalar_text(&args[0])?;
            let units = &text.utf16;
            let mut length = units.len();
            if dialect != SqlDialect::NativeV1 {
                length -= units
                    .windows(2)
                    .filter(|w| {
                        (0xd800..=0xdbff).contains(&w[0]) && (0xdc00..=0xdfff).contains(&w[1])
                    })
                    .count();
            }
            Ok(SqlValue::I64(Signed64(length as i64)))
        }
        "mdd_cast" => cast(
            args[0].clone(),
            &scalar_text(&args[1])?.strict_utf8()?,
            dialect,
            control,
        ),
        "mdd_like" => {
            let has_escape = integer(&args[3])? != 0;
            if has_escape && args[2] == SqlValue::Null {
                return Ok(SqlValue::Null);
            }
            let value = scalar_text(&args[0])?;
            let pattern = scalar_text(&args[1])?;
            let escape = if !has_escape {
                None
            } else {
                let escape = scalar_text(&args[2])?;
                if escape.utf16.len() != 1 {
                    return Err(invalid("LIKE_ESCAPE_REQUIRES_ONE_UTF16_UNIT"));
                }
                Some(escape.utf16[0])
            };
            Ok(SqlValue::Bool(like(
                &value, &pattern, escape, dialect, control,
            )?))
        }
        "mdd_concat" => {
            if let (Some(left), Some(right)) = (args[0].bytes(), args[1].bytes()) {
                if left.len() as u64 + right.len() as u64 > control.inner.limits.max_cell_bytes {
                    return Err(quota("BLOB_CONCAT_CELL_BYTES"));
                }
                let mut bytes = left.to_vec();
                bytes.extend(right);
                return Ok(SqlValue::Bytes(bytes));
            }
            let mut left = scalar_text(&args[0])?;
            let right = scalar_text(&args[1])?;
            if (left.utf16.len() as u64 + right.utf16.len() as u64) * 2
                > control.inner.limits.max_cell_bytes
            {
                return Err(quota("CONCAT_CELL_BYTES"));
            }
            left.utf16.extend(right.utf16);
            left.original_mutf8 = None;
            Ok(SqlValue::Text(left))
        }
        "mdd_lower" | "mdd_upper" => {
            let mut text = scalar_text(&args[0])?;
            for value in &mut text.utf16 {
                if name == "mdd_lower" && (65..=90).contains(value) {
                    *value += 32;
                } else if name == "mdd_upper" && (97..=122).contains(value) {
                    *value -= 32;
                }
            }
            text.original_mutf8 = None;
            Ok(SqlValue::Text(text))
        }
        "mdd_neg" => {
            if dialect != SqlDialect::NativeV1
                && matches!(
                    args[0],
                    SqlValue::Text(_) | SqlValue::Bytes(_) | SqlValue::DexMutf8 { .. }
                )
            {
                return Err(MddError::new(
                    mdd_types::ErrorCode::UnsupportedQuery,
                    "sql.numeric",
                    "LEGACY_TEXT_NUMERIC_COERCION_NOT_IMPLEMENTED",
                ));
            }
            if let SqlValue::F64(bits) = args[0] {
                Ok(SqlValue::F64(DecimalU64(bits.0 ^ (1u64 << 63))))
            } else {
                integer_value(-integer(&args[0])?, false)
            }
        }
        "mdd_pos" => Ok(args[0].clone()),
        "mdd_eq" | "mdd_ne" | "mdd_gt" | "mdd_ge" | "mdd_lt" | "mdd_le" | "mdd_literal_eq"
        | "mdd_literal_ne" | "mdd_literal_gt" | "mdd_literal_ge" | "mdd_literal_lt"
        | "mdd_literal_le" => {
            let (order, operator) = if let Some(operator) = name.strip_prefix("mdd_literal_") {
                (compare_literal(&args[0], &args[1])?, operator)
            } else {
                (compare(&args[0], &args[1])?, &name[4..])
            };
            Ok(SqlValue::Bool(match operator {
                "eq" => order == Ordering::Equal,
                "ne" => order != Ordering::Equal,
                "gt" => order == Ordering::Greater,
                "ge" => order != Ordering::Less,
                "lt" => order == Ordering::Less,
                _ => order != Ordering::Greater,
            }))
        }
        "mdd_add" | "mdd_sub" | "mdd_mul" | "mdd_div" | "mdd_mod" => {
            if dialect != SqlDialect::NativeV1
                && args.iter().any(|value| {
                    matches!(
                        value,
                        SqlValue::Text(_) | SqlValue::Bytes(_) | SqlValue::DexMutf8 { .. }
                    )
                })
            {
                return Err(MddError::new(
                    mdd_types::ErrorCode::UnsupportedQuery,
                    "sql.numeric",
                    "LEGACY_TEXT_NUMERIC_COERCION_NOT_IMPLEMENTED",
                ));
            }
            numeric(&args[0], &args[1], &name[4..])
        }
        _ => Err(invalid("INTERNAL_UNKNOWN_SCALAR")),
    }
}
fn failure(control: &SqlControl, error: MddError) -> rusqlite::Error {
    rusqlite::Error::UserFunctionError(Box::new(control.fail(error)))
}
fn args(context: &Context<'_>) -> MddResult<Vec<SqlValue>> {
    (0..context.len())
        .map(|i| SqlValue::from_sqlite(context.get_raw(i)))
        .collect()
}
pub(crate) fn register(
    db: &Connection,
    dialect: SqlDialect,
    control: SqlControl,
) -> rusqlite::Result<()> {
    let flags = FunctionFlags::SQLITE_UTF8
        | FunctionFlags::SQLITE_DETERMINISTIC
        | FunctionFlags::SQLITE_INNOCUOUS;
    // Return a SQLite-native value only for truth coercion. SQLite then owns
    // the AND/OR/NOT/IS TRUE and NULL rules. Lossy text here cannot enter a
    // result or comparison; non-ASCII surrogate units cannot be numeric text.
    let truth_control = control.clone();
    db.create_scalar_function("mdd_truth_input", 1, flags, move |context| {
        truth_control
            .checkpoint(1, false)
            .map_err(|e| failure(&truth_control, e))?;
        let value =
            SqlValue::from_sqlite(context.get_raw(0)).map_err(|e| failure(&truth_control, e))?;
        Ok(match value {
            SqlValue::Null => Cell::Null,
            SqlValue::Bool(v) => Cell::Integer(i64::from(v)),
            SqlValue::I64(v) => Cell::Integer(v.0),
            SqlValue::U64(v) => {
                i64::try_from(v.0).map_or_else(|_| Cell::Real(v.0 as f64), Cell::Integer)
            }
            SqlValue::F64(v) => Cell::Real(f64::from_bits(v.0)),
            SqlValue::Text(v) => Cell::Text(String::from_utf16_lossy(&v.utf16)),
            SqlValue::Bytes(v) | SqlValue::DexMutf8 { bytes: v, .. } => Cell::Blob(v),
        })
    })?;
    for (name, count) in [
        ("mdd_length", 1),
        ("mdd_substr", 2),
        ("mdd_substr", 3),
        ("mdd_hex", 1),
        ("mdd_lower", 1),
        ("mdd_upper", 1),
        ("mdd_neg", 1),
        ("mdd_pos", 1),
        ("mdd_key", 1),
        ("mdd_sort_key", 1),
        ("mdd_nullif", 2),
        ("mdd_eq", 2),
        ("mdd_ne", 2),
        ("mdd_gt", 2),
        ("mdd_ge", 2),
        ("mdd_lt", 2),
        ("mdd_le", 2),
        ("mdd_literal_eq", 2),
        ("mdd_literal_ne", 2),
        ("mdd_literal_gt", 2),
        ("mdd_literal_ge", 2),
        ("mdd_literal_lt", 2),
        ("mdd_literal_le", 2),
        ("mdd_concat", 2),
        ("mdd_cast", 2),
        ("mdd_add", 2),
        ("mdd_sub", 2),
        ("mdd_mul", 2),
        ("mdd_div", 2),
        ("mdd_mod", 2),
        ("mdd_like", 4),
    ] {
        let control = control.clone();
        db.create_scalar_function(name, count, flags, move |context| {
            let values = args(context).map_err(|e| failure(&control, e))?;
            let value =
                scalar(name, &values, dialect, &control).map_err(|e| failure(&control, e))?;
            value
                .sqlite(control.inner.limits.max_cell_bytes)
                .map_err(|e| failure(&control, e))
        })?;
    }
    for name in ["mdd_min", "mdd_max", "mdd_sum"] {
        db.create_aggregate_function(
            name,
            1,
            flags,
            AggregateValue {
                name,
                control: control.clone(),
            },
        )?;
    }
    Ok(())
}
struct AggregateValue {
    name: &'static str,
    control: SqlControl,
}
impl Aggregate<Option<SqlValue>, Cell> for AggregateValue {
    fn init(&self, _: &mut Context<'_>) -> rusqlite::Result<Option<SqlValue>> {
        Ok(None)
    }
    fn step(
        &self,
        context: &mut Context<'_>,
        state: &mut Option<SqlValue>,
    ) -> rusqlite::Result<()> {
        self.control
            .checkpoint(1, false)
            .map_err(|e| failure(&self.control, e))?;
        let value =
            SqlValue::from_sqlite(context.get_raw(0)).map_err(|e| failure(&self.control, e))?;
        if value == SqlValue::Null {
            return Ok(());
        }
        if let Some(previous) = state {
            if self.name == "mdd_sum" {
                *previous =
                    numeric(previous, &value, "add").map_err(|e| failure(&self.control, e))?;
            } else {
                let order = compare(previous, &value).map_err(|e| failure(&self.control, e))?;
                if (self.name == "mdd_min" && order == Ordering::Greater)
                    || (self.name == "mdd_max" && order == Ordering::Less)
                {
                    *previous = value;
                }
            }
        } else {
            *state = Some(value);
        }
        Ok(())
    }
    fn finalize(
        &self,
        _: &mut Context<'_>,
        state: Option<Option<SqlValue>>,
    ) -> rusqlite::Result<Cell> {
        state
            .flatten()
            .unwrap_or(SqlValue::Null)
            .sqlite(self.control.inner.limits.max_cell_bytes)
            .map_err(|e| failure(&self.control, e))
    }
}
