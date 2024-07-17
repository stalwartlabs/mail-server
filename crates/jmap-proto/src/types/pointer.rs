/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use crate::parser::{json::Parser, JsonObjectParser};

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub enum JSONPointer {
    Root,
    Wildcard,
    String(String),
    Number(u64),
    Path(Vec<JSONPointer>),
}

enum TokenType {
    Unknown,
    Number,
    String,
    Wildcard,
    Escaped,
}

impl JsonObjectParser for JSONPointer {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut path = Vec::new();
        let mut num = 0u64;
        let mut buf = Vec::new();
        let mut token = TokenType::Unknown;
        let mut start_pos = parser.pos;

        while let Some(ch) = parser.next_char() {
            match (ch, &token) {
                (b'0'..=b'9', TokenType::Unknown | TokenType::Number) => {
                    num = num.saturating_mul(10).saturating_add((ch - b'0') as u64);
                    token = TokenType::Number;
                }
                (b'*', TokenType::Unknown) => {
                    token = TokenType::Wildcard;
                }
                (b'0', TokenType::Escaped) => {
                    buf.push(b'~');
                    token = TokenType::String;
                }
                (b'1', TokenType::Escaped) => {
                    buf.push(b'/');
                    token = TokenType::String;
                }
                (b'/' | b'"', _) => {
                    match token {
                        TokenType::String => {
                            path.push(JSONPointer::String(
                                String::from_utf8(buf).map_err(|_| parser.error_utf8())?,
                            ));
                            buf = Vec::new();
                        }
                        TokenType::Number => {
                            path.push(JSONPointer::Number(num));
                            num = 0;
                        }
                        TokenType::Wildcard => {
                            path.push(JSONPointer::Wildcard);
                        }
                        TokenType::Unknown if parser.pos_marker != start_pos => {
                            path.push(JSONPointer::String(String::new()));
                        }
                        _ => (),
                    }

                    if ch == b'/' {
                        token = TokenType::Unknown;
                        start_pos = parser.pos;
                    } else {
                        parser.is_eof = true;
                        return Ok(match path.len() {
                            1 => path.pop().unwrap(),
                            0 => JSONPointer::Root,
                            _ => JSONPointer::Path(path),
                        });
                    }
                }
                (_, _) => {
                    if matches!(&token, TokenType::Number | TokenType::Wildcard)
                        && parser.pos - 1 > start_pos
                    {
                        buf.extend_from_slice(
                            parser
                                .bytes
                                .get(start_pos..parser.pos - 1)
                                .unwrap_or_default(),
                        );
                    }

                    token = match ch {
                        b'~' if !matches!(&token, TokenType::Escaped) => TokenType::Escaped,
                        b'\\' => {
                            buf.push(parser.next_char().unwrap_or(b'\\'));
                            TokenType::String
                        }
                        _ => {
                            buf.push(ch);
                            TokenType::String
                        }
                    };
                }
            }
        }

        Err(parser.error_unterminated())
    }
}

impl JSONPointer {
    pub fn to_string(&self) -> Option<&str> {
        match self {
            JSONPointer::String(s) => s.as_str().into(),
            _ => None,
        }
    }

    pub fn unwrap_string(self) -> Option<String> {
        match self {
            JSONPointer::String(s) => s.into(),
            _ => None,
        }
    }

    pub fn item_query(&self) -> Option<&str> {
        match self {
            JSONPointer::String(property) => property.as_str().into(),
            JSONPointer::Path(path) if path.len() == 2 => {
                if let (Some(JSONPointer::String(property)), Some(JSONPointer::Wildcard)) =
                    (path.first(), path.get(1))
                {
                    property.as_str().into()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn item_subquery(&self) -> Option<(&str, &str)> {
        match self {
            JSONPointer::Path(path) if path.len() == 3 => {
                match (path.first(), path.get(1), path.get(2)) {
                    (
                        Some(JSONPointer::String(root)),
                        Some(JSONPointer::Wildcard),
                        Some(JSONPointer::String(property)),
                    ) => Some((root.as_str(), property.as_str())),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

impl Display for JSONPointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JSONPointer::Root => write!(f, "/"),
            JSONPointer::Wildcard => write!(f, "*"),
            JSONPointer::String(s) => write!(f, "{}", s),
            JSONPointer::Number(n) => write!(f, "{}", n),
            JSONPointer::Path(path) => {
                for (i, ptr) in path.iter().enumerate() {
                    if i > 0 {
                        write!(f, "/")?;
                    }
                    write!(f, "{}", ptr)?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::json::Parser;

    use super::JSONPointer;

    #[test]
    fn json_pointer_parse() {
        for (input, output) in vec![
            ("hello", JSONPointer::String("hello".to_string())),
            ("9a", JSONPointer::String("9a".to_string())),
            ("a9", JSONPointer::String("a9".to_string())),
            ("*a", JSONPointer::String("*a".to_string())),
            (
                "/hello/world",
                JSONPointer::Path(vec![
                    JSONPointer::String("hello".to_string()),
                    JSONPointer::String("world".to_string()),
                ]),
            ),
            ("*", JSONPointer::Wildcard),
            (
                "/hello/*",
                JSONPointer::Path(vec![
                    JSONPointer::String("hello".to_string()),
                    JSONPointer::Wildcard,
                ]),
            ),
            ("1234", JSONPointer::Number(1234)),
            (
                "/hello/1234",
                JSONPointer::Path(vec![
                    JSONPointer::String("hello".to_string()),
                    JSONPointer::Number(1234),
                ]),
            ),
            ("~0~1", JSONPointer::String("~/".to_string())),
            (
                "/hello/~0~1",
                JSONPointer::Path(vec![
                    JSONPointer::String("hello".to_string()),
                    JSONPointer::String("~/".to_string()),
                ]),
            ),
            (
                "/hello/1~0~1/*~1~0",
                JSONPointer::Path(vec![
                    JSONPointer::String("hello".to_string()),
                    JSONPointer::String("1~/".to_string()),
                    JSONPointer::String("*/~".to_string()),
                ]),
            ),
            (
                "/hello/world/*/99",
                JSONPointer::Path(vec![
                    JSONPointer::String("hello".to_string()),
                    JSONPointer::String("world".to_string()),
                    JSONPointer::Wildcard,
                    JSONPointer::Number(99),
                ]),
            ),
            ("/", JSONPointer::String("".to_string())),
            (
                "///",
                JSONPointer::Path(vec![
                    JSONPointer::String("".to_string()),
                    JSONPointer::String("".to_string()),
                    JSONPointer::String("".to_string()),
                ]),
            ),
            ("", JSONPointer::Root),
        ] {
            assert_eq!(
                Parser::new(format!("\"{input}\"").as_bytes())
                    .next_token::<JSONPointer>()
                    .unwrap()
                    .unwrap_string("")
                    .unwrap(),
                output,
                "{input}"
            );
        }
    }
}
