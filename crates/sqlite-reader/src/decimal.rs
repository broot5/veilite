//! Decimal parsing compatible with SQLite 3.51.0 sqlite3AtoF (src/util.c).
//! Preserve its bounded significand and double-double operation order. Do not
//! replace these operations with fused multiply-add or Rust's decimal parser.

fn multiply(pair: &mut [f64; 2], factor: f64, correction: f64) {
    let high = f64::from_bits(pair[0].to_bits() & 0xffff_ffff_fc00_0000);
    let factor_high = f64::from_bits(factor.to_bits() & 0xffff_ffff_fc00_0000);
    let low = pair[0] - high;
    let factor_low = factor - factor_high;
    let product = high * factor_high;
    let cross = high * factor_low + low * factor_high;
    let sum = product + cross;
    let residual = product - sum + cross + low * factor_low;
    let residual = pair[0] * correction + pair[1] * factor + residual;
    pair[0] = sum + residual;
    pair[1] = (sum - pair[0]) + residual;
}

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
    while exponent > 0 && significand < (u64::MAX - 0x7ff) / 10 {
        significand *= 10;
        exponent -= 1;
    }
    while exponent < 0 && significand.is_multiple_of(10) {
        significand /= 10;
        exponent += 1;
    }
    let high = significand as f64;
    let low = if high <= 18_446_744_073_709_549_568.0 {
        let rounded = high as u64;
        if significand >= rounded {
            (significand - rounded) as f64
        } else {
            -((rounded - significand) as f64)
        }
    } else {
        0.0
    };
    let mut pair = [high, low];
    // Beyond these bounds every nonzero bounded significand over/underflows.
    // This also bounds work for arbitrarily long numeric tokens.
    if exponent > 400 {
        return Some(if negative {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        });
    }
    if exponent < -400 {
        return Some(if negative { -0.0 } else { 0.0 });
    }
    while exponent >= 100 {
        multiply(&mut pair, 1e100, -1.590_289_110_975_991_8e83);
        exponent -= 100;
    }
    while exponent >= 10 {
        multiply(&mut pair, 1e10, 0.0);
        exponent -= 10;
    }
    while exponent >= 1 {
        multiply(&mut pair, 10.0, 0.0);
        exponent -= 1;
    }
    while exponent <= -100 {
        multiply(&mut pair, 1e-100, -1.999_189_980_260_288_3e-117);
        exponent += 100;
    }
    while exponent <= -10 {
        multiply(&mut pair, 1e-10, -3.643_219_731_549_774e-27);
        exponent += 10;
    }
    while exponent <= -1 {
        multiply(&mut pair, 0.1, -5.551_115_123_125_783e-18);
        exponent += 1;
    }
    let value = pair[0] + pair[1];
    let value = if value.is_nan() { f64::INFINITY } else { value };
    Some(if negative { -value } else { value })
}
