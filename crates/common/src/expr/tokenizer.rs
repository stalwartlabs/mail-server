/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, iter::Peekable, slice::Iter, time::Duration};

use ahash::AHashMap;
use regex::Regex;
use utils::config::utils::ParseValue;

use super::{
    functions::{ASYNC_FUNCTIONS, FUNCTIONS},
    *,
};

pub struct Tokenizer<'x> {
    pub(crate) iter: Peekable<Iter<'x, u8>>,
    token_map: &'x TokenMap,
    buf: Vec<u8>,
    depth: u32,
    next_token: Vec<Token>,
    has_number: bool,
    has_dot: bool,
    has_alpha: bool,
    is_start: bool,
    is_eof: bool,
}

#[derive(Debug, Default, Clone)]
pub struct TokenMap {
    pub tokens: AHashMap<&'static str, Token>,
}

impl<'x> Tokenizer<'x> {
    #[allow(clippy::should_implement_trait)]
    pub fn new(expr: &'x str, token_map: &'x TokenMap) -> Self {
        Self {
            iter: expr.as_bytes().iter().peekable(),
            buf: Vec::new(),
            depth: 0,
            next_token: Vec::with_capacity(2),
            has_number: false,
            has_dot: false,
            has_alpha: false,
            is_start: true,
            is_eof: false,
            token_map,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Token>, String> {
        if let Some(token) = self.next_token.pop() {
            return Ok(Some(token));
        } else if self.is_eof {
            return Ok(None);
        }

        while let Some(&ch) = self.iter.next() {
            match ch {
                b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'$' => {
                    self.buf.push(ch);
                    self.has_alpha = true;
                }
                b'0'..=b'9' => {
                    self.buf.push(ch);
                    self.has_number = true;
                }
                b'.' => {
                    self.buf.push(ch);
                    self.has_dot = true;
                }
                b'}' => {
                    self.is_eof = true;
                    break;
                }
                b'-' if self.buf.last().map_or(false, |c| *c == b'[') => {
                    self.buf.push(ch);
                }
                b':' if self.buf.contains(&b'.') => {
                    self.buf.push(ch);
                }
                b']' if self.buf.contains(&b'[') => {
                    self.buf.push(b']');
                }
                b'*' if self.buf.last().map_or(false, |&c| c == b'[' || c == b'.') => {
                    self.buf.push(ch);
                }
                _ => {
                    let (prev_token, ch) = if ch == b'(' && self.buf.eq(b"matches") {
                        // Parse regular expressions
                        let stop_ch = self.find_char(&[b'\"', b'\''])?;
                        let regex_str = self.parse_string(stop_ch)?;
                        let regex = Regex::new(&regex_str).map_err(|e| {
                            format!("Invalid regular expression {:?}: {}", regex_str, e)
                        })?;
                        self.has_alpha = false;
                        self.buf.clear();
                        self.find_char(&[b','])?;
                        (Token::Regex(regex).into(), b'(')
                    } else if !self.buf.is_empty() {
                        self.is_start = false;
                        (self.parse_buf()?.into(), ch)
                    } else {
                        (None, ch)
                    };
                    let token = match ch {
                        b'&' => {
                            if matches!(self.iter.peek(), Some(b'&')) {
                                self.iter.next();
                            }
                            Token::BinaryOperator(BinaryOperator::And)
                        }
                        b'|' => {
                            if matches!(self.iter.peek(), Some(b'|')) {
                                self.iter.next();
                            }
                            Token::BinaryOperator(BinaryOperator::Or)
                        }
                        b'!' => {
                            if matches!(self.iter.peek(), Some(b'=')) {
                                self.iter.next();
                                Token::BinaryOperator(BinaryOperator::Ne)
                            } else {
                                Token::UnaryOperator(UnaryOperator::Not)
                            }
                        }
                        b'^' => Token::BinaryOperator(BinaryOperator::Xor),
                        b'(' => {
                            self.depth += 1;
                            Token::OpenParen
                        }
                        b')' => {
                            if self.depth == 0 {
                                return Err("Unmatched close parenthesis".to_string());
                            }
                            self.depth -= 1;
                            Token::CloseParen
                        }
                        b'+' => Token::BinaryOperator(BinaryOperator::Add),
                        b'*' => Token::BinaryOperator(BinaryOperator::Multiply),
                        b'/' => Token::BinaryOperator(BinaryOperator::Divide),
                        b'-' => {
                            if self.is_start {
                                Token::UnaryOperator(UnaryOperator::Minus)
                            } else {
                                Token::BinaryOperator(BinaryOperator::Subtract)
                            }
                        }
                        b'=' => match self.iter.next() {
                            Some(b'=') => Token::BinaryOperator(BinaryOperator::Eq),
                            Some(b'>') => Token::BinaryOperator(BinaryOperator::Ge),
                            Some(b'<') => Token::BinaryOperator(BinaryOperator::Le),
                            _ => Token::BinaryOperator(BinaryOperator::Eq),
                        },
                        b'>' => match self.iter.peek() {
                            Some(b'=') => {
                                self.iter.next();
                                Token::BinaryOperator(BinaryOperator::Ge)
                            }
                            _ => Token::BinaryOperator(BinaryOperator::Gt),
                        },
                        b'<' => match self.iter.peek() {
                            Some(b'=') => {
                                self.iter.next();
                                Token::BinaryOperator(BinaryOperator::Le)
                            }
                            _ => Token::BinaryOperator(BinaryOperator::Lt),
                        },
                        b',' => Token::Comma,
                        b'[' => Token::OpenBracket,
                        b']' => Token::CloseBracket,
                        b' ' | b'\r' | b'\n' => {
                            if prev_token.is_some() {
                                return Ok(prev_token);
                            } else {
                                continue;
                            }
                        }
                        b'\"' | b'\'' => Token::Constant(Constant::String(self.parse_string(ch)?)),
                        _ => {
                            return Err(format!("Invalid character {:?}", char::from(ch),));
                        }
                    };
                    self.is_start = matches!(
                        token,
                        Token::OpenParen | Token::Comma | Token::BinaryOperator(_)
                    );

                    return if prev_token.is_some() {
                        self.next_token.push(token);
                        Ok(prev_token)
                    } else {
                        Ok(Some(token))
                    };
                }
            }
        }

        if self.depth > 0 {
            Err("Unmatched open parenthesis".to_string())
        } else if !self.buf.is_empty() {
            self.parse_buf().map(Some)
        } else {
            Ok(None)
        }
    }

    fn find_char(&mut self, chars: &[u8]) -> Result<u8, String> {
        for &ch in self.iter.by_ref() {
            if !ch.is_ascii_whitespace() {
                return if chars.contains(&ch) {
                    Ok(ch)
                } else {
                    Err(format!(
                        "Expected {:?}, found invalid character {:?}",
                        char::from(chars[0]),
                        char::from(ch),
                    ))
                };
            }
        }

        Err("Unexpected end of expression".to_string())
    }

    fn parse_string(&mut self, stop_ch: u8) -> Result<String, String> {
        let mut buf = Vec::with_capacity(16);
        let mut last_ch = 0;
        let mut found_end = false;

        for &ch in self.iter.by_ref() {
            if last_ch != b'\\' {
                if ch != stop_ch {
                    buf.push(ch);
                } else {
                    found_end = true;
                    break;
                }
            } else {
                match ch {
                    b'n' => {
                        buf.push(b'\n');
                    }
                    b'r' => {
                        buf.push(b'\r');
                    }
                    b't' => {
                        buf.push(b'\t');
                    }
                    _ => {
                        buf.push(ch);
                    }
                }
            }

            last_ch = ch;
        }

        if found_end {
            String::from_utf8(buf).map_err(|_| "Invalid UTF-8".to_string())
        } else {
            Err("Unterminated string".to_string())
        }
    }

    fn parse_buf(&mut self) -> Result<Token, String> {
        let buf = String::from_utf8(std::mem::take(&mut self.buf)).unwrap_or_default();
        if self.has_number && !self.has_alpha {
            self.has_number = false;
            if self.has_dot {
                self.has_dot = false;

                buf.parse::<f64>()
                    .map(|f| Token::Constant(Constant::Float(f)))
                    .map_err(|_| format!("Invalid float value {}", buf,))
            } else {
                buf.parse::<i64>()
                    .map(|i| Token::Constant(Constant::Integer(i)))
                    .map_err(|_| format!("Invalid integer value {}", buf,))
            }
        } else {
            let has_dot = self.has_dot;
            let has_number = self.has_number;

            self.has_alpha = false;
            self.has_number = false;
            self.has_dot = false;

            if !has_number && !has_dot && [4, 5].contains(&buf.len()) {
                if buf == "true" {
                    return Ok(Token::Constant(Constant::Integer(1)));
                } else if buf == "false" {
                    return Ok(Token::Constant(Constant::Integer(0)));
                }
            }

            if let Some(regex_capture) = buf.strip_prefix('$').and_then(|v| v.parse::<u32>().ok()) {
                Ok(Token::Capture(regex_capture))
            } else if let Some((idx, (name, _, num_args))) = FUNCTIONS
                .iter()
                .enumerate()
                .find(|(_, (name, _, _))| name == &buf)
            {
                Ok(Token::Function {
                    name: Cow::Borrowed(*name),
                    id: idx as u32,
                    num_args: *num_args,
                })
            } else if let Some((name, idx, num_args)) =
                ASYNC_FUNCTIONS.iter().find(|(name, _, _)| name == &buf)
            {
                Ok(Token::Function {
                    name: Cow::Borrowed(*name),
                    id: *idx + FUNCTIONS.len() as u32,
                    num_args: *num_args,
                })
            } else if let Some(token) = self.token_map.tokens.get(buf.as_str()) {
                Ok(token.clone())
            } else if let Ok(duration) = Duration::parse_value(&buf) {
                Ok(Token::Constant(Constant::Integer(
                    duration.as_millis() as i64
                )))
            } else {
                Err(format!("Invalid variable or constant {buf:?}"))
            }
        }
    }
}

impl TokenMap {
    pub fn with_all_variables(self) -> Self {
        self.with_variables(&[
            V_RECIPIENT,
            V_RECIPIENT_DOMAIN,
            V_SENDER,
            V_SENDER_DOMAIN,
            V_MX,
            V_HELO_DOMAIN,
            V_AUTHENTICATED_AS,
            V_LISTENER,
            V_REMOTE_IP,
            V_REMOTE_PORT,
            V_LOCAL_IP,
            V_LOCAL_PORT,
            V_PRIORITY,
            V_PROTOCOL,
            V_TLS,
            V_QUEUE_RETRY_NUM,
            V_QUEUE_NOTIFY_NUM,
            V_QUEUE_EXPIRES_IN,
            V_QUEUE_LAST_STATUS,
            V_QUEUE_LAST_ERROR,
        ])
    }

    pub fn with_variables(mut self, variables: &[u32]) -> Self {
        for (name, idx) in VARIABLES_MAP {
            if variables.contains(idx) {
                self.tokens.insert(name, Token::Variable(*idx));
            }
        }

        self
    }

    pub fn with_variables_map<I>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (&'static str, u32)>,
    {
        for (name, idx) in vars {
            self.tokens.insert(name, Token::Variable(idx));
        }

        self
    }

    pub fn set_constants<I, T>(mut self, consts: I) -> Self
    where
        I: IntoIterator<Item = (&'static str, T)>,
        T: Into<Constant>,
    {
        for (name, constant) in consts {
            self.tokens.insert(name, Token::Constant(constant.into()));
        }

        self
    }

    pub fn with_constants<T: ConstantValue>(mut self) -> Self {
        T::add_constants(&mut self);
        self
    }

    pub fn add_constant(&mut self, name: &'static str, constant: impl Into<Constant>) -> &mut Self {
        self.tokens.insert(name, Token::Constant(constant.into()));
        self
    }
}
