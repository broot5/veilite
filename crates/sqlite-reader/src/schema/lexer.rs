use super::Result;

#[derive(Debug)]
pub(super) enum Token {
    Word(String, bool),
    String(String),
    Number(String),
    Blob(Vec<u8>),
    Symbol(char),
}
impl Token {
    pub(super) fn kw(&self, expected: &str) -> bool {
        matches!(self, Self::Word(word, false) if word.eq_ignore_ascii_case(expected))
    }
    pub(super) fn symbol(&self, expected: char) -> bool {
        matches!(self, Self::Symbol(c) if *c == expected)
    }
    pub(super) fn name(&self) -> Option<&str> {
        match self {
            Self::Word(s, _) | Self::String(s) => Some(s),
            _ => None,
        }
    }
    pub(super) fn spelling(&self) -> String {
        match self {
            Self::Word(s, _) | Self::String(s) | Self::Number(s) => s.clone(),
            Self::Symbol(c) => c.to_string(),
            Self::Blob(_) => String::new(),
        }
    }
}

pub(super) fn lex(sql: &str) -> Result<Vec<Token>> {
    let b = sql.as_bytes();
    let mut i = 0;
    let mut tokens = Vec::new();
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b[i..].starts_with(b"--") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b[i..].starts_with(b"/*") {
            i += 2;
            while i < b.len() && !b[i..].starts_with(b"*/") {
                i += 1;
            }
            if i == b.len() {
                return Err("unterminated SQL comment");
            }
            i += 2;
            continue;
        }
        let blob = matches!(b[i], b'x' | b'X') && b.get(i + 1) == Some(&b'\'');
        if blob {
            i += 1;
        }
        if matches!(b[i], b'\'' | b'"' | b'`' | b'[') {
            let quote = b[i];
            let end = if quote == b'[' { b']' } else { quote };
            i += 1;
            let mut value = Vec::new();
            loop {
                if i == b.len() {
                    return Err("unterminated quoted SQL token");
                }
                if b[i] == end {
                    i += 1;
                    if quote != b'[' && b.get(i) == Some(&end) {
                        value.push(end);
                        i += 1;
                    } else {
                        break;
                    }
                } else {
                    value.push(b[i]);
                    i += 1;
                }
            }
            let value = String::from_utf8(value).map_err(|_| "invalid SQL text")?;
            tokens.push(if blob {
                if value.len() % 2 != 0 {
                    return Err("invalid blob literal");
                }
                let mut out = Vec::new();
                for pair in value.as_bytes().chunks_exact(2) {
                    let high = (pair[0] as char)
                        .to_digit(16)
                        .ok_or("invalid blob literal")?;
                    let low = (pair[1] as char)
                        .to_digit(16)
                        .ok_or("invalid blob literal")?;
                    out.push((high * 16 + low) as u8);
                }
                Token::Blob(out)
            } else if quote == b'\'' {
                Token::String(value)
            } else {
                Token::Word(value, true)
            });
            continue;
        }
        if b[i].is_ascii_digit() || (b[i] == b'.' && b.get(i + 1).is_some_and(u8::is_ascii_digit)) {
            let start = i;
            i += 1;
            while i < b.len()
                && (b[i].is_ascii_alphanumeric()
                    || matches!(b[i], b'.' | b'_')
                    || (matches!(b[i], b'+' | b'-') && matches!(b[i - 1], b'e' | b'E')))
            {
                i += 1;
            }
            tokens.push(Token::Number(sql[start..i].into()));
            continue;
        }
        if b[i].is_ascii_alphabetic() || b[i] == b'_' || b[i] >= 128 {
            let start = i;
            i += 1;
            while i < b.len()
                && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'_' | b'$') || b[i] >= 128)
            {
                i += 1;
            }
            tokens.push(Token::Word(sql[start..i].into(), false));
            continue;
        }
        if !b[i].is_ascii() {
            return Err("invalid SQL token");
        }
        tokens.push(Token::Symbol(b[i] as char));
        i += 1;
    }
    Ok(tokens)
}
