/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use crate::error::{method::MethodError, request::RequestError};

use self::json::Parser;

pub mod base32;
pub mod impls;
pub mod json;

#[derive(Debug, PartialEq, Clone)]
pub enum Token<T> {
    Colon,
    Comma,
    DictStart,
    DictEnd,
    ArrayStart,
    ArrayEnd,
    Integer(i64),
    Float(f64),
    Boolean(bool),
    String(T),
    Null,
}

impl<T: PartialEq> Eq for Token<T> {}

pub trait JsonObjectParser {
    fn parse(parser: &mut Parser<'_>) -> Result<Self>
    where
        Self: Sized;
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Request(RequestError),
    Method(MethodError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ignore {}

impl<T: Eq> Token<T> {
    pub fn unwrap_string(self, property: &str) -> Result<T> {
        match self {
            Token::String(s) => Ok(s),
            token => Err(token.error(property, "string")),
        }
    }

    pub fn unwrap_string_or_null(self, property: &str) -> Result<Option<T>> {
        match self {
            Token::String(s) => Ok(Some(s)),
            Token::Null => Ok(None),
            token => Err(token.error(property, "string")),
        }
    }

    pub fn unwrap_bool(self, property: &str) -> Result<bool> {
        match self {
            Token::Boolean(v) => Ok(v),
            token => Err(token.error(property, "boolean")),
        }
    }

    pub fn unwrap_bool_or_null(self, property: &str) -> Result<Option<bool>> {
        match self {
            Token::Boolean(v) => Ok(Some(v)),
            Token::Null => Ok(None),
            token => Err(token.error(property, "boolean")),
        }
    }

    pub fn unwrap_usize_or_null(self, property: &str) -> Result<Option<usize>> {
        match self {
            Token::Integer(v) if v >= 0 => Ok(Some(v as usize)),
            Token::Float(v) if v >= 0.0 => Ok(Some(v as usize)),
            Token::Null => Ok(None),
            token => Err(token.error(property, "unsigned integer")),
        }
    }

    pub fn unwrap_uint_or_null(self, property: &str) -> Result<Option<u64>> {
        match self {
            Token::Integer(v) if v >= 0 => Ok(Some(v as u64)),
            Token::Float(v) if v >= 0.0 => Ok(Some(v as u64)),
            Token::Null => Ok(None),
            token => Err(token.error(property, "unsigned integer")),
        }
    }

    pub fn unwrap_int_or_null(self, property: &str) -> Result<Option<i64>> {
        match self {
            Token::Integer(v) => Ok(Some(v)),
            Token::Float(v) => Ok(Some(v as i64)),
            Token::Null => Ok(None),
            token => Err(token.error(property, "unsigned integer")),
        }
    }

    pub fn unwrap_ints_or_null(self, property: &str) -> Result<Option<i32>> {
        match self {
            Token::Integer(v) => Ok(Some(v as i32)),
            Token::Float(v) => Ok(Some(v as i32)),
            Token::Null => Ok(None),
            token => Err(token.error(property, "unsigned integer")),
        }
    }

    pub fn assert(self, token: Token<T>) -> Result<()> {
        if self == token {
            Ok(())
        } else {
            Err(self.error("", &token.to_string()))
        }
    }

    pub fn assert_jmap(self, token: Token<T>) -> Result<()> {
        if self == token {
            Ok(())
        } else {
            Err(Error::Request(RequestError::not_request(format!(
                "Invalid JMAP request: expected '{token}', got '{self}'."
            ))))
        }
    }

    pub fn error(&self, property: &str, expected: &str) -> Error {
        Error::Method(MethodError::InvalidArguments(if !property.is_empty() {
            format!("Invalid argument for '{property:?}': expected '{expected}', got '{self}'.",)
        } else {
            format!("Invalid argument: expected '{expected}', got '{self}'.")
        }))
    }
}

impl Display for Ignore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "string")
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Request(RequestError::not_json(&s))
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Request(RequestError::not_json(s))
    }
}

impl<T> Display for Token<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Colon => write!(f, ":"),
            Token::Comma => write!(f, ","),
            Token::DictStart => write!(f, "{{"),
            Token::DictEnd => write!(f, "}}"),
            Token::ArrayStart => write!(f, "["),
            Token::ArrayEnd => write!(f, "]"),
            Token::Integer(i) => write!(f, "{}", i),
            Token::Float(v) => write!(f, "{}", v),
            Token::Boolean(b) => write!(f, "{}", b),
            Token::Null => write!(f, "null"),
            Token::String(_) => write!(f, "string"),
        }
    }
}
