//! Constant default values and SQLite column affinity.
use crate::{Text, TextEncoding, Value, schema::Affinity};
type Result<T> = std::result::Result<T, &'static str>;

// SQLite valueFromExpr keeps floating-point and oversized decimal tokens as
// strings under TEXT affinity. CAST(real AS TEXT) follows a different path.
pub(crate) fn number_literal(
    text: &str,
    affinity: Affinity,
    encoding: TextEncoding,
) -> Result<Value> {
    let unsigned = text.trim_start_matches(['+', '-']);
    let hex = unsigned.starts_with("0x") || unsigned.starts_with("0X");
    let bytes = text.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if *byte == b'_' {
            let digit = |b: &u8| {
                if hex {
                    b.is_ascii_hexdigit()
                } else {
                    b.is_ascii_digit()
                }
            };
            if i == 0
                || !bytes.get(i - 1).is_some_and(digit)
                || !bytes.get(i + 1).is_some_and(digit)
            {
                return Err("invalid numeric separator");
            }
        }
    }
    let normalized = text.replace('_', "");
    let text = normalized.as_str();
    let unsigned = text.trim_start_matches(['+', '-']);
    let value = if hex {
        let n = u64::from_str_radix(&unsigned[2..], 16).map_err(|_| "unsupported hex literal")?;
        let n = i64::from_be_bytes(n.to_be_bytes());
        if text.starts_with('-') {
            n.checked_neg()
                .map(Value::Integer)
                .unwrap_or(Value::Real(-(i64::MIN as f64)))
        } else {
            Value::Integer(n)
        }
    } else {
        number(text)?
    };
    if affinity == Affinity::Text {
        // The only REAL produced by a hex literal is negation of i64::MIN.
        // SQLite formats that computed value rather than preserving the token.
        if hex && matches!(value, Value::Real(_)) {
            return Ok(Value::Text(Text::encode("9.22337203685478e+18", encoding)));
        }
        if !hex && unsigned.parse::<i64>().is_err() {
            return Ok(Value::Text(Text::encode(
                text.trim_start_matches('+'),
                encoding,
            )));
        }
    }
    Ok(value)
}

// Numeric text uses decimal syntax; SQL-only hex and separators are handled above.
fn number(text: &str) -> Result<Value> {
    if let Ok(value) = text.parse::<i64>() {
        return Ok(Value::Integer(value));
    }
    let value = crate::decimal::parse(text).ok_or("unsupported numeric literal")?;
    if value.is_nan() {
        return Err("invalid numeric literal");
    }
    Ok(Value::Real(value))
}

pub(crate) fn coerce(value: Value, affinity: Affinity, encoding: TextEncoding) -> Result<Value> {
    let value = match (affinity, value) {
        (Affinity::Text, Value::Integer(n)) => Value::Text(Text::encode(&n.to_string(), encoding)),
        (Affinity::Integer | Affinity::Numeric | Affinity::Real, Value::Text(text)) => {
            let s = text.to_string().map_err(|_| "invalid default text")?;
            let s = s.trim_matches(|c: char| c.is_ascii_whitespace());
            number(s).unwrap_or(Value::Text(text))
        }
        (_, value) => value,
    };
    Ok(match (affinity, value) {
        (Affinity::Real, Value::Integer(n)) => Value::Real(n as f64),
        // SQLite's numeric affinity first integerizes zero, losing its sign.
        (Affinity::Real, Value::Real(0.0)) => Value::Real(0.0),
        (Affinity::Integer | Affinity::Numeric, Value::Real(n))
            // SQLite leaves floating-point endpoint values as REAL: a value
            // just outside i64 can round to the same f64 as i64::MIN.
            if n > i64::MIN as f64 && n < -(i64::MIN as f64) && n.fract() == 0.0 =>
        {
            Value::Integer(n as i64)
        }
        (_, value) => value,
    })
}
