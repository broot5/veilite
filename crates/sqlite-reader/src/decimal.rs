//! Decimal parsing with SQLite 3.53.4 sqlite3AtoF significand retention.

/// Parses a complete ASCII decimal, without whitespace or SQL separators.
pub(crate) fn parse(text: &str) -> Option<f64> {
    const LIMIT: u64 = (u64::MAX - 9) / 10;
    let bytes = text.as_bytes();
    let mut at = 0;
    let negative = bytes.first() == Some(&b'-');
    if matches!(bytes.first(), Some(b'+' | b'-')) {
        at += 1;
    }
    let mut significand = 0u64;
    let mut shift = 0i64;
    let mut digits = 0usize;
    while let Some(&digit) = bytes.get(at).filter(|b| b.is_ascii_digit()) {
        if significand < LIMIT {
            significand = significand * 10 + u64::from(digit - b'0');
        } else {
            shift += 1;
        }
        digits += 1;
        at += 1;
    }
    if bytes.get(at) == Some(&b'.') {
        at += 1;
        while let Some(&digit) = bytes.get(at).filter(|b| b.is_ascii_digit()) {
            if significand < LIMIT {
                significand = significand * 10 + u64::from(digit - b'0');
                shift -= 1;
            }
            digits += 1;
            at += 1;
        }
    }
    let mut exponent = 0i64;
    if matches!(bytes.get(at), Some(b'e' | b'E')) {
        at += 1;
        let minus = bytes.get(at) == Some(&b'-');
        if matches!(bytes.get(at), Some(b'+' | b'-')) {
            at += 1;
        }
        let start = at;
        while let Some(&digit) = bytes.get(at).filter(|b| b.is_ascii_digit()) {
            exponent = if exponent < 10000 {
                exponent * 10 + i64::from(digit - b'0')
            } else {
                10000
            };
            at += 1;
        }
        if at == start {
            return None;
        }
        if minus {
            exponent = -exponent;
        }
    }
    if at != bytes.len() || digits == 0 {
        return None;
    }
    if significand == 0 {
        return Some(if negative { -0.0 } else { 0.0 });
    }
    exponent += shift;
    // SQLite 3.53.4 converts the retained u64 significand times 10^exponent
    // to the nearest binary64. Parse only that bounded decimal, not the input:
    // digits discarded above must not influence rounding.
    let value = format!("{significand}e{exponent}").parse::<f64>().ok()?;
    Some(if negative { -value } else { value })
}

#[cfg(test)]
mod tests {
    #[test]
    fn decimal_bits_match_sqlite() {
        for line in include_str!("../tests/fixtures/decimal.tsv").lines() {
            let (literal, bits) = line.split_once('\t').unwrap();
            assert_eq!(
                super::parse(literal).unwrap().to_bits(),
                u64::from_str_radix(bits, 16).unwrap(),
                "{literal}"
            );
        }
        for invalid in [
            "", "+", ".", "1e", "1e+", "1.2.3", "NaN", "inf", "1_0", "--1",
        ] {
            assert!(super::parse(invalid).is_none(), "{invalid}");
        }
    }
}
