/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, iter::Peekable, slice::Iter};

use crate::request::method::MethodObject;

use super::{Ignore, JsonObjectParser, Token};

const MAX_NESTED_LEVELS: u32 = 16;

#[derive(Debug)]
pub struct Parser<'x> {
    pub bytes: &'x [u8],
    pub iter: Peekable<Iter<'x, u8>>,
    pub next_ch: Option<u8>,
    pub pos: usize,
    pub pos_marker: usize,
    pub depth_array: u32,
    pub depth_dict: u32,
    pub is_eof: bool,
    pub ctx: MethodObject,
}

impl<'x> Parser<'x> {
    pub fn new(bytes: &'x [u8]) -> Self {
        Self {
            bytes,
            iter: bytes.iter().peekable(),
            next_ch: None,
            pos: 0,
            pos_marker: 0,
            is_eof: false,
            depth_array: 0,
            depth_dict: 0,
            ctx: MethodObject::Core,
        }
    }

    pub fn error(&self, message: &str) -> trc::Error {
        trc::JmapEvent::NotJson
            .into_err()
            .details(format!("{message} at position {}.", self.pos))
    }

    pub fn error_unterminated(&self) -> trc::Error {
        trc::JmapEvent::NotJson.into_err().details(format!(
            "Unterminated string at position {pos}.",
            pos = self.pos
        ))
    }

    pub fn error_utf8(&self) -> trc::Error {
        trc::JmapEvent::NotJson.into_err().details(format!(
            "Invalid UTF-8 sequence at position {pos}.",
            pos = self.pos
        ))
    }

    pub fn error_value(&mut self) -> trc::Error {
        if self.is_eof || self.skip_string() {
            trc::JmapEvent::InvalidArguments.into_err().details(format!(
                "Invalid value {:?} at position {}.",
                String::from_utf8_lossy(self.bytes[self.pos_marker..self.pos - 1].as_ref()),
                self.pos
            ))
        } else {
            self.error_unterminated()
        }
    }

    #[inline(always)]
    pub fn peek_char(&mut self) -> Option<u8> {
        self.iter.peek().map(|&&ch| ch)
    }

    #[inline(always)]
    pub fn next_char(&mut self) -> Option<u8> {
        self.pos += 1;
        self.iter.next().copied()
    }

    #[inline(always)]
    pub fn next_unescaped(&mut self) -> trc::Result<Option<u8>> {
        match self.next_char() {
            Some(b'"') => {
                self.is_eof = true;
                Ok(None)
            }
            Some(b'\\') => self
                .next_char()
                .ok_or_else(|| self.error_unterminated())
                .map(Some),
            Some(ch) => Ok(Some(ch)),
            None => {
                if self.is_eof {
                    Ok(None)
                } else {
                    Err(self.error_unterminated())
                }
            }
        }
    }

    pub fn skip_string(&mut self) -> bool {
        let mut last_ch = 0;

        while let Some(ch) = self.next_char() {
            if ch == b'"' && last_ch != b'\\' {
                self.is_eof = true;
                return true;
            } else {
                last_ch = ch;
            }
        }

        false
    }

    pub fn next_token<T: JsonObjectParser>(&mut self) -> trc::Result<Token<T>> {
        let mut next_ch = self.next_ch.take().or_else(|| self.next_char());

        while let Some(mut ch) = next_ch {
            match ch {
                b'"' => {
                    self.pos_marker = self.pos;
                    self.is_eof = false;
                    let value = T::parse(self)?;
                    return if self.is_eof || self.skip_string() {
                        Ok(Token::String(value))
                    } else {
                        Err(self.error_unterminated())
                    };
                }
                b',' => {
                    return Ok(Token::Comma);
                }
                b':' => {
                    return Ok(Token::Colon);
                }
                b'[' => {
                    if self.depth_array + self.depth_dict < MAX_NESTED_LEVELS {
                        self.depth_array += 1;
                        return Ok(Token::ArrayStart);
                    } else {
                        return Err(self.error("Too many nested objects"));
                    }
                }
                b']' => {
                    return if self.depth_array != 0 {
                        self.depth_array -= 1;
                        Ok(Token::ArrayEnd)
                    } else {
                        Err(self.error("Unexpected array end"))
                    };
                }
                b'{' => {
                    if self.depth_array + self.depth_dict < MAX_NESTED_LEVELS {
                        self.depth_dict += 1;
                        return Ok(Token::DictStart);
                    } else {
                        return Err(self.error("Too many nested objects"));
                    }
                }
                b'}' => {
                    return if self.depth_dict != 0 {
                        self.depth_dict -= 1;
                        Ok(Token::DictEnd)
                    } else {
                        Err(self.error("Unexpected dictionary end"))
                    };
                }
                b'0'..=b'9' | b'-' | b'+' => {
                    let mut num: i64 = 0;
                    let mut is_float = false;
                    let mut is_negative = false;
                    let num_start = self.pos - 1;

                    loop {
                        match ch {
                            b'-' => {
                                is_negative = true;
                            }
                            b'0'..=b'9' => {
                                if !is_float {
                                    num = num.saturating_mul(10).saturating_add((ch - b'0') as i64);
                                }
                            }
                            b',' | b']' | b'}' => {
                                self.next_ch = ch.into();
                                break;
                            }
                            b'+' => (),
                            b'.' | b'e' | b'E' => {
                                is_float = true;
                            }
                            b' ' | b'\r' | b'\t' | b'\n' => {
                                break;
                            }
                            _ => {
                                return Err(self
                                    .error(&format!("Unexpected character {:?}", char::from(ch))));
                            }
                        }

                        ch = self.next_char().ok_or_else(|| self.error_unterminated())?;
                    }

                    return if !is_float {
                        Ok(Token::Integer(if !is_negative { num } else { -num }))
                    } else {
                        fast_float::parse(
                            self.bytes.get(num_start..self.pos - 1).unwrap_or_default(),
                        )
                        .map(Token::Float)
                        .map_err(|_| {
                            self.error(&format!(
                                "Failed to parse number {:?}",
                                String::from_utf8_lossy(
                                    self.bytes.get(num_start..self.pos - 1).unwrap_or_default()
                                )
                            ))
                        })
                    };
                }
                b't' => {
                    return if let (Some(b'r'), Some(b'u'), Some(b'e')) =
                        (self.iter.next(), self.iter.next(), self.iter.next())
                    {
                        self.pos += 3;
                        Ok(Token::Boolean(true))
                    } else {
                        Err(self.error("Invalid JSON token"))
                    };
                }
                b'f' => {
                    return if let (Some(b'a'), Some(b'l'), Some(b's'), Some(b'e')) = (
                        self.iter.next(),
                        self.iter.next(),
                        self.iter.next(),
                        self.iter.next(),
                    ) {
                        self.pos += 4;
                        Ok(Token::Boolean(false))
                    } else {
                        Err(self.error("Invalid JSON token"))
                    };
                }
                b'n' => {
                    return if let (Some(b'u'), Some(b'l'), Some(b'l')) =
                        (self.iter.next(), self.iter.next(), self.iter.next())
                    {
                        self.pos += 3;
                        Ok(Token::Null)
                    } else {
                        Err(self.error("Invalid JSON token"))
                    };
                }
                b' ' | b'\t' | b'\r' | b'\n' => (),
                _ => {
                    return Err(self.error(&format!("Unexpected character {:?}", char::from(ch))));
                }
            }

            next_ch = self.next_char();
        }

        Err(self.error("Unexpected EOF"))
    }

    pub fn next_dict_key<T: JsonObjectParser + Display + Eq>(&mut self) -> trc::Result<Option<T>> {
        loop {
            match self.next_token::<T>()? {
                Token::String(k) => {
                    self.next_token::<T>()?.assert(Token::Colon)?;
                    return Ok(Some(k));
                }
                Token::Comma => (),
                Token::DictEnd => return Ok(None),
                token => {
                    return Err(self.error(&format!("Expected object property, found {}", token)))
                }
            }
        }
    }

    pub fn skip_token(&mut self, start_depth_array: u32, start_depth_dict: u32) -> trc::Result<()> {
        while {
            self.next_token::<Ignore>()?;
            start_depth_array != self.depth_array || start_depth_dict != self.depth_dict
        } {}

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::parser::Token;

    use super::Parser;

    #[test]
    fn parse_json() {
        for (input, expected_result) in [
            (
                &b"[true, false, 123, 456 , -123, 0.123, -0.456, 3.7e-5, 6.02e+23, null]"[..],
                vec![
                    Token::ArrayStart,
                    Token::Boolean(true),
                    Token::Comma,
                    Token::Boolean(false),
                    Token::Comma,
                    Token::Integer(123),
                    Token::Comma,
                    Token::Integer(456),
                    Token::Comma,
                    Token::Integer(-123),
                    Token::Comma,
                    Token::Float(0.123),
                    Token::Comma,
                    Token::Float(-0.456),
                    Token::Comma,
                    Token::Float(3.7e-5),
                    Token::Comma,
                    Token::Float(6.02e23),
                    Token::Comma,
                    Token::Null,
                    Token::ArrayEnd,
                ],
            ),
            (
                &b"{\"\": true, \"\": false , \"\": {\"\": 123}, \"\": [ ]}"[..],
                vec![
                    Token::DictStart,
                    Token::String("".to_string()),
                    Token::Colon,
                    Token::Boolean(true),
                    Token::Comma,
                    Token::String("".to_string()),
                    Token::Colon,
                    Token::Boolean(false),
                    Token::Comma,
                    Token::String("".to_string()),
                    Token::Colon,
                    Token::DictStart,
                    Token::String("".to_string()),
                    Token::Colon,
                    Token::Integer(123),
                    Token::DictEnd,
                    Token::Comma,
                    Token::String("".to_string()),
                    Token::Colon,
                    Token::ArrayStart,
                    Token::ArrayEnd,
                    Token::DictEnd,
                ],
            ),
        ] {
            let mut p = Parser::new(input);
            let mut result = Vec::new();
            while let Ok(token) = p.next_token() {
                result.push(token);
            }

            assert_eq!(result, expected_result);
        }

        for (input, expected_result) in [
            ("hello\t\nworld", "hello\t\nworld"),
            ("hello\t\n\\\"world\\\"\\n", "hello\t\n\"world\"\n"),
            ("\\\"hello\\\tworld\\\"", "\"hello\tworld\""),
            ("\\u0009\\u0020\\u263A", "\t ☺"),
            ("", ""),
        ] {
            assert_eq!(
                Parser::new(format!("\"{input}\"").as_bytes())
                    .next_token::<String>()
                    .unwrap()
                    .unwrap_string("")
                    .unwrap(),
                expected_result
            );
        }
    }
}
