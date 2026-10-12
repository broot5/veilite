use super::Result;

#[derive(Debug)]
pub(super) struct Token {
    pub(super) kind: TokenKind,
    pub(super) span: std::ops::Range<usize>,
}

#[derive(Debug)]
pub(super) enum TokenKind {
    Word(String, bool),
    String(String),
    Number(String),
    Blob(Vec<u8>),
    Symbol(char),
}
impl Token {
    pub(super) fn kw(&self, expected: &str) -> bool {
        matches!(&self.kind, TokenKind::Word(word, false) if word.eq_ignore_ascii_case(expected))
    }
    pub(super) fn symbol(&self, expected: char) -> bool {
        matches!(&self.kind, TokenKind::Symbol(c) if *c == expected)
    }
    pub(super) fn name(&self) -> Option<&str> {
        match &self.kind {
            TokenKind::Word(s, _) | TokenKind::String(s) => Some(s),
            _ => None,
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
        let start = i;
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
            let kind = if blob {
                if value.len() % 2 != 0 {
                    return Err("invalid blob literal");
                }
                let mut out = Vec::new();
                for pair in value.as_bytes().as_chunks::<2>().0 {
                    let high = (pair[0] as char)
                        .to_digit(16)
                        .ok_or("invalid blob literal")?;
                    let low = (pair[1] as char)
                        .to_digit(16)
                        .ok_or("invalid blob literal")?;
                    out.push((high * 16 + low) as u8);
                }
                TokenKind::Blob(out)
            } else if quote == b'\'' {
                TokenKind::String(value)
            } else {
                TokenKind::Word(value, true)
            };
            tokens.push(Token {
                kind,
                span: start..i,
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
            tokens.push(Token {
                kind: TokenKind::Number(sql[start..i].into()),
                span: start..i,
            });
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
            tokens.push(Token {
                kind: TokenKind::Word(sql[start..i].into(), false),
                span: start..i,
            });
            continue;
        }
        if !b[i].is_ascii() {
            return Err("invalid SQL token");
        }
        tokens.push(Token {
            kind: TokenKind::Symbol(b[i] as char),
            span: i..i + 1,
        });
        i += 1;
    }
    Ok(tokens)
}
