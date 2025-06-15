/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use crate::json::{JsonPointer, JsonPointerItem};

use super::{JsonObjectParser, json::Parser};

enum TokenType {
    Unknown,
    Number,
    String,
    Wildcard,
    Escaped,
}

impl JsonObjectParser for JsonPointer {
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
                            path.push(JsonPointerItem::String(
                                String::from_utf8(buf).map_err(|_| parser.error_utf8())?,
                            ));
                            buf = Vec::new();
                        }
                        TokenType::Number => {
                            path.push(JsonPointerItem::Number(num));
                            num = 0;
                        }
                        TokenType::Wildcard => {
                            path.push(JsonPointerItem::Wildcard);
                        }
                        TokenType::Unknown if parser.pos_marker != start_pos => {
                            path.push(JsonPointerItem::String(String::new()));
                        }
                        _ => (),
                    }

                    if ch == b'/' {
                        token = TokenType::Unknown;
                        start_pos = parser.pos;
                    } else {
                        parser.is_eof = true;

                        if path.is_empty() {
                            path.push(JsonPointerItem::Root);
                        }

                        return Ok(JsonPointer(path));
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

impl Display for JsonPointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, ptr) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, "/")?;
            }
            write!(f, "{}", ptr)?;
        }
        Ok(())
    }
}

impl Display for JsonPointerItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonPointerItem::Root => write!(f, "/"),
            JsonPointerItem::Wildcard => write!(f, "*"),
            JsonPointerItem::String(s) => write!(f, "{}", s),
            JsonPointerItem::Number(n) => write!(f, "{}", n),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::json::parser::json::Parser;

    use super::{JsonPointer, JsonPointerItem};

    #[test]
    fn json_pointer_parse() {
        for (input, output) in vec![
            ("hello", vec![JsonPointerItem::String("hello".to_string())]),
            ("9a", vec![JsonPointerItem::String("9a".to_string())]),
            ("a9", vec![JsonPointerItem::String("a9".to_string())]),
            ("*a", vec![JsonPointerItem::String("*a".to_string())]),
            (
                "/hello/world",
                vec![
                    JsonPointerItem::String("hello".to_string()),
                    JsonPointerItem::String("world".to_string()),
                ],
            ),
            ("*", vec![JsonPointerItem::Wildcard]),
            (
                "/hello/*",
                vec![
                    JsonPointerItem::String("hello".to_string()),
                    JsonPointerItem::Wildcard,
                ],
            ),
            ("1234", vec![JsonPointerItem::Number(1234)]),
            (
                "/hello/1234",
                vec![
                    JsonPointerItem::String("hello".to_string()),
                    JsonPointerItem::Number(1234),
                ],
            ),
            ("~0~1", vec![JsonPointerItem::String("~/".to_string())]),
            (
                "/hello/~0~1",
                vec![
                    JsonPointerItem::String("hello".to_string()),
                    JsonPointerItem::String("~/".to_string()),
                ],
            ),
            (
                "/hello/1~0~1/*~1~0",
                vec![
                    JsonPointerItem::String("hello".to_string()),
                    JsonPointerItem::String("1~/".to_string()),
                    JsonPointerItem::String("*/~".to_string()),
                ],
            ),
            (
                "/hello/world/*/99",
                vec![
                    JsonPointerItem::String("hello".to_string()),
                    JsonPointerItem::String("world".to_string()),
                    JsonPointerItem::Wildcard,
                    JsonPointerItem::Number(99),
                ],
            ),
            ("/", vec![JsonPointerItem::String("".to_string())]),
            (
                "///",
                vec![
                    JsonPointerItem::String("".to_string()),
                    JsonPointerItem::String("".to_string()),
                    JsonPointerItem::String("".to_string()),
                ],
            ),
            ("", vec![JsonPointerItem::Root]),
        ] {
            assert_eq!(
                Parser::new(format!("\"{input}\"").as_bytes())
                    .next_token::<JsonPointer>()
                    .unwrap()
                    .unwrap_string("")
                    .unwrap()
                    .0,
                output,
                "{input}"
            );
        }
    }
}
