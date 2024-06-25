/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

pub const V_RECIPIENT: u32 = 0;
pub const V_RECIPIENT_DOMAIN: u32 = 1;
pub const V_SENDER: u32 = 2;
pub const V_SENDER_DOMAIN: u32 = 3;
pub const V_MX: u32 = 4;
pub const V_HELO_DOMAIN: u32 = 5;
pub const V_AUTHENTICATED_AS: u32 = 6;
pub const V_LISTENER: u32 = 7;
pub const V_REMOTE_IP: u32 = 8;
pub const V_REMOTE_PORT: u32 = 9;
pub const V_LOCAL_IP: u32 = 10;
pub const V_LOCAL_PORT: u32 = 11;
pub const V_PRIORITY: u32 = 12;
pub const V_PROTOCOL: u32 = 13;
pub const V_TLS: u32 = 14;
pub const V_RECIPIENTS: u32 = 15;
pub const V_QUEUE_RETRY_NUM: u32 = 16;
pub const V_QUEUE_NOTIFY_NUM: u32 = 17;
pub const V_QUEUE_EXPIRES_IN: u32 = 18;
pub const V_QUEUE_LAST_STATUS: u32 = 19;
pub const V_QUEUE_LAST_ERROR: u32 = 20;

pub const VARIABLES_MAP: &[(&str, u32)] = &[
    ("rcpt", V_RECIPIENT),
    ("rcpt_domain", V_RECIPIENT_DOMAIN),
    ("sender", V_SENDER),
    ("sender_domain", V_SENDER_DOMAIN),
    ("mx", V_MX),
    ("helo_domain", V_HELO_DOMAIN),
    ("authenticated_as", V_AUTHENTICATED_AS),
    ("listener", V_LISTENER),
    ("remote_ip", V_REMOTE_IP),
    ("local_ip", V_LOCAL_IP),
    ("priority", V_PRIORITY),
    ("local_port", V_LOCAL_PORT),
    ("remote_port", V_REMOTE_PORT),
    ("protocol", V_PROTOCOL),
    ("is_tls", V_TLS),
    ("recipients", V_RECIPIENTS),
    ("retry_num", V_QUEUE_RETRY_NUM),
    ("notify_num", V_QUEUE_NOTIFY_NUM),
    ("expires_in", V_QUEUE_EXPIRES_IN),
    ("last_status", V_QUEUE_LAST_STATUS),
    ("last_error", V_QUEUE_LAST_ERROR),
];

use regex::Regex;
use utils::config::{utils::ParseValue, Rate};

use self::tokenizer::TokenMap;

pub mod eval;
pub mod functions;
pub mod if_block;
pub mod parser;
pub mod tokenizer;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Expression {
    pub items: Vec<ExpressionItem>,
}

#[derive(Debug, Clone)]
pub enum ExpressionItem {
    Variable(u32),
    Capture(u32),
    Constant(Constant),
    BinaryOperator(BinaryOperator),
    UnaryOperator(UnaryOperator),
    Regex(Regex),
    JmpIf { val: bool, pos: u32 },
    Function { id: u32, num_args: u32 },
    ArrayAccess,
    ArrayBuild(u32),
}

#[derive(Debug)]
pub enum Variable<'x> {
    String(Cow<'x, str>),
    Integer(i64),
    Float(f64),
    Array(Vec<Variable<'x>>),
}

impl Default for Variable<'_> {
    fn default() -> Self {
        Variable::String("".into())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Constant {
    Integer(i64),
    Float(f64),
    String(String),
}

impl Eq for Constant {}

impl From<String> for Constant {
    fn from(value: String) -> Self {
        Constant::String(value)
    }
}

impl From<bool> for Constant {
    fn from(value: bool) -> Self {
        Constant::Integer(value as i64)
    }
}

impl From<i64> for Constant {
    fn from(value: i64) -> Self {
        Constant::Integer(value)
    }
}

impl From<i32> for Constant {
    fn from(value: i32) -> Self {
        Constant::Integer(value as i64)
    }
}

impl From<i16> for Constant {
    fn from(value: i16) -> Self {
        Constant::Integer(value as i64)
    }
}

impl From<f64> for Constant {
    fn from(value: f64) -> Self {
        Constant::Float(value)
    }
}

impl From<usize> for Constant {
    fn from(value: usize) -> Self {
        Constant::Integer(value as i64)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BinaryOperator {
    Add,
    Subtract,
    Multiply,
    Divide,

    And,
    Or,
    Xor,

    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UnaryOperator {
    Not,
    Minus,
}

#[derive(Debug, Clone)]
pub enum Token {
    Variable(u32),
    Capture(u32),
    Function {
        name: Cow<'static, str>,
        id: u32,
        num_args: u32,
    },
    Constant(Constant),
    Regex(Regex),
    BinaryOperator(BinaryOperator),
    UnaryOperator(UnaryOperator),
    OpenParen,
    CloseParen,
    OpenBracket,
    CloseBracket,
    Comma,
}

impl From<usize> for Variable<'_> {
    fn from(value: usize) -> Self {
        Variable::Integer(value as i64)
    }
}

impl From<i64> for Variable<'_> {
    fn from(value: i64) -> Self {
        Variable::Integer(value)
    }
}

impl From<u64> for Variable<'_> {
    fn from(value: u64) -> Self {
        Variable::Integer(value as i64)
    }
}

impl From<i32> for Variable<'_> {
    fn from(value: i32) -> Self {
        Variable::Integer(value as i64)
    }
}

impl From<u32> for Variable<'_> {
    fn from(value: u32) -> Self {
        Variable::Integer(value as i64)
    }
}

impl From<u16> for Variable<'_> {
    fn from(value: u16) -> Self {
        Variable::Integer(value as i64)
    }
}

impl From<i16> for Variable<'_> {
    fn from(value: i16) -> Self {
        Variable::Integer(value as i64)
    }
}

impl From<f64> for Variable<'_> {
    fn from(value: f64) -> Self {
        Variable::Float(value)
    }
}

impl<'x> From<&'x str> for Variable<'x> {
    fn from(value: &'x str) -> Self {
        Variable::String(Cow::Borrowed(value))
    }
}

impl From<String> for Variable<'_> {
    fn from(value: String) -> Self {
        Variable::String(Cow::Owned(value))
    }
}

impl<'x> From<Vec<Variable<'x>>> for Variable<'x> {
    fn from(value: Vec<Variable<'x>>) -> Self {
        Variable::Array(value)
    }
}

impl From<bool> for Variable<'_> {
    fn from(value: bool) -> Self {
        Variable::Integer(value as i64)
    }
}

impl<T: Into<Constant>> From<T> for Expression {
    fn from(value: T) -> Self {
        Expression {
            items: vec![ExpressionItem::Constant(value.into())],
        }
    }
}

impl PartialEq for ExpressionItem {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Variable(l0), Self::Variable(r0)) => l0 == r0,
            (Self::Constant(l0), Self::Constant(r0)) => l0 == r0,
            (Self::BinaryOperator(l0), Self::BinaryOperator(r0)) => l0 == r0,
            (Self::UnaryOperator(l0), Self::UnaryOperator(r0)) => l0 == r0,
            (Self::Regex(_), Self::Regex(_)) => true,
            (
                Self::JmpIf {
                    val: l_val,
                    pos: l_pos,
                },
                Self::JmpIf {
                    val: r_val,
                    pos: r_pos,
                },
            ) => l_val == r_val && l_pos == r_pos,
            (
                Self::Function {
                    id: l_id,
                    num_args: l_num_args,
                },
                Self::Function {
                    id: r_id,
                    num_args: r_num_args,
                },
            ) => l_id == r_id && l_num_args == r_num_args,
            (Self::ArrayBuild(l0), Self::ArrayBuild(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl Eq for ExpressionItem {}

impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Variable(l0), Self::Variable(r0)) => l0 == r0,
            (
                Self::Function {
                    name: l_name,
                    id: l_id,
                    num_args: l_num_args,
                },
                Self::Function {
                    name: r_name,
                    id: r_id,
                    num_args: r_num_args,
                },
            ) => l_name == r_name && l_id == r_id && l_num_args == r_num_args,
            (Self::Constant(l0), Self::Constant(r0)) => l0 == r0,
            (Self::Regex(_), Self::Regex(_)) => true,
            (Self::BinaryOperator(l0), Self::BinaryOperator(r0)) => l0 == r0,
            (Self::UnaryOperator(l0), Self::UnaryOperator(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl Eq for Token {}

pub struct NoConstants;

pub trait ConstantValue:
    ParseValue + for<'x> TryFrom<Variable<'x>> + Into<Constant> + Sized
{
    fn add_constants(token_map: &mut TokenMap);
}

impl ConstantValue for () {
    fn add_constants(_: &mut TokenMap) {}
}

impl From<()> for Constant {
    fn from(_: ()) -> Self {
        Constant::Integer(0)
    }
}

impl<'x> TryFrom<Variable<'x>> for () {
    type Error = ();

    fn try_from(_: Variable<'x>) -> Result<Self, Self::Error> {
        Ok(())
    }
}

impl ConstantValue for Duration {
    fn add_constants(_: &mut TokenMap) {}
}

impl<'x> TryFrom<Variable<'x>> for Duration {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Integer(value) if value > 0 => Ok(Duration::from_millis(value as u64)),
            Variable::Float(value) if value > 0.0 => Ok(Duration::from_millis(value as u64)),
            Variable::String(value) if !value.is_empty() => {
                Duration::parse_value(&value).map_err(|_| ())
            }
            _ => Err(()),
        }
    }
}

impl From<Duration> for Constant {
    fn from(value: Duration) -> Self {
        Constant::Integer(value.as_millis() as i64)
    }
}

impl<'x> TryFrom<Variable<'x>> for Rate {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Array(items) if items.len() == 2 => {
                let requests = items[0].to_integer().ok_or(())?;
                let period = items[1].to_integer().ok_or(())?;

                if requests > 0 && period > 0 {
                    Ok(Rate {
                        requests: requests as u64,
                        period: Duration::from_millis(period as u64),
                    })
                } else {
                    Err(())
                }
            }
            _ => Err(()),
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for Ipv4Addr {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::String(value) => value.parse().map_err(|_| ()),
            _ => Err(()),
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for Ipv6Addr {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::String(value) => value.parse().map_err(|_| ()),
            _ => Err(()),
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for IpAddr {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::String(value) => value.parse().map_err(|_| ()),
            _ => Err(()),
        }
    }
}

impl<'x, T: TryFrom<Variable<'x>>> TryFrom<Variable<'x>> for Vec<T>
where
    Result<Vec<T>, ()>: FromIterator<Result<T, <T as TryFrom<Variable<'x>>>::Error>>,
{
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        value
            .into_array()
            .into_iter()
            .map(|v| T::try_from(v))
            .collect()
    }
}
