/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{cmp::Ordering, fmt::Display};

use compact_str::{CompactString, ToCompactString, format_compact};
use hyper::StatusCode;
use trc::EvalEvent;

use crate::Server;

use super::{
    BinaryOperator, Constant, Expression, ExpressionItem, Setting, StringCow, UnaryOperator,
    Variable,
    functions::{FUNCTIONS, ResolveVariable},
    if_block::IfBlock,
};

impl Server {
    pub async fn eval_if<'x, R: TryFrom<Variable<'x>>, V: ResolveVariable>(
        &'x self,
        if_block: &'x IfBlock,
        resolver: &'x V,
        session_id: u64,
    ) -> Option<R> {
        if if_block.is_empty() {
            trc::event!(
                Eval(EvalEvent::Result),
                SpanId = session_id,
                Id = if_block.key.clone(),
                Result = ""
            );

            return None;
        }

        match (EvalContext {
            resolver,
            core: self,
            expr: if_block,
            captures: Vec::new(),
            session_id,
        })
        .eval()
        .await
        {
            Ok(result) => {
                trc::event!(
                    Eval(EvalEvent::Result),
                    SpanId = session_id,
                    Id = if_block.key.clone(),
                    Result = format!("{result:?}"),
                );

                match result.try_into() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        trc::event!(
                            Eval(EvalEvent::Result),
                            SpanId = session_id,
                            Id = if_block.key.clone(),
                            Result = "",
                        );

                        None
                    }
                }
            }
            Err(err) => {
                trc::event!(
                    Eval(EvalEvent::Error),
                    SpanId = session_id,
                    Id = if_block.key.clone(),
                    CausedBy = err,
                );

                None
            }
        }
    }

    pub async fn eval_expr<'x, R: TryFrom<Variable<'x>>, V: ResolveVariable>(
        &'x self,
        expr: &'x Expression,
        resolver: &'x V,
        expr_id: &str,
        session_id: u64,
    ) -> Option<R> {
        if expr.is_empty() {
            return None;
        }

        match (EvalContext {
            resolver,
            core: self,
            expr,
            captures: &mut Vec::new(),
            session_id,
        })
        .eval()
        .await
        {
            Ok(result) => {
                trc::event!(
                    Eval(EvalEvent::Result),
                    SpanId = session_id,
                    Id = expr_id.to_compact_string(),
                    Result = format!("{result:?}"),
                );

                match result.try_into() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        trc::event!(
                            Eval(EvalEvent::Error),
                            SpanId = session_id,
                            Id = expr_id.to_compact_string(),
                            Details = "Failed to convert result",
                        );

                        None
                    }
                }
            }
            Err(err) => {
                trc::event!(
                    Eval(EvalEvent::Error),
                    SpanId = session_id,
                    Id = expr_id.to_compact_string(),
                    CausedBy = err,
                );

                None
            }
        }
    }
}

struct EvalContext<'x, V: ResolveVariable, T, C> {
    resolver: &'x V,
    core: &'x Server,
    expr: &'x T,
    captures: C,
    session_id: u64,
}

impl<'x, V: ResolveVariable> EvalContext<'x, V, IfBlock, Vec<CompactString>> {
    async fn eval(&mut self) -> trc::Result<Variable<'x>> {
        for if_then in &self.expr.if_then {
            if (EvalContext {
                resolver: self.resolver,
                core: self.core,
                expr: &if_then.expr,
                captures: &mut self.captures,
                session_id: self.session_id,
            })
            .eval()
            .await?
            .to_bool()
            {
                return (EvalContext {
                    resolver: self.resolver,
                    core: self.core,
                    expr: &if_then.then,
                    captures: &mut self.captures,
                    session_id: self.session_id,
                })
                .eval()
                .await;
            }
        }

        (EvalContext {
            resolver: self.resolver,
            core: self.core,
            expr: &self.expr.default,
            captures: &mut self.captures,
            session_id: self.session_id,
        })
        .eval()
        .await
    }
}

impl<'x, V: ResolveVariable> EvalContext<'x, V, Expression, &mut Vec<CompactString>> {
    async fn eval(&mut self) -> trc::Result<Variable<'x>> {
        let mut stack = Vec::new();
        let mut exprs = self.expr.items.iter();

        while let Some(expr) = exprs.next() {
            match expr {
                ExpressionItem::Variable(v) => {
                    stack.push(self.resolver.resolve_variable(*v));
                }
                ExpressionItem::Global(v) => {
                    stack.push(self.resolver.resolve_global(v));
                }
                ExpressionItem::Constant(val) => {
                    stack.push(Variable::from(val));
                }
                ExpressionItem::Capture(v) => {
                    stack.push(Variable::String(StringCow::Owned(
                        self.captures
                            .get(*v as usize)
                            .map(|v| v.as_str())
                            .unwrap_or_default()
                            .to_compact_string(),
                    )));
                }
                ExpressionItem::Setting(setting) => match setting {
                    Setting::Hostname => {
                        stack.push(self.core.core.network.server_name.as_str().into())
                    }
                    Setting::ReportDomain => {
                        stack.push(self.core.core.network.report_domain.as_str().into())
                    }
                    Setting::NodeId => stack.push(self.core.core.network.node_id.into()),
                    Setting::Other(key) => stack.push(
                        self.core
                            .core
                            .storage
                            .config
                            .get(key)
                            .await?
                            .unwrap_or_default()
                            .to_compact_string()
                            .into(),
                    ),
                },
                ExpressionItem::UnaryOperator(op) => {
                    let value = stack.pop().unwrap_or_default();
                    stack.push(match op {
                        UnaryOperator::Not => value.op_not(),
                        UnaryOperator::Minus => value.op_minus(),
                    });
                }
                ExpressionItem::BinaryOperator(op) => {
                    let right = stack.pop().unwrap_or_default();
                    let left = stack.pop().unwrap_or_default();
                    stack.push(match op {
                        BinaryOperator::Add => left.op_add(right),
                        BinaryOperator::Subtract => left.op_subtract(right),
                        BinaryOperator::Multiply => left.op_multiply(right),
                        BinaryOperator::Divide => left.op_divide(right),
                        BinaryOperator::And => left.op_and(right),
                        BinaryOperator::Or => left.op_or(right),
                        BinaryOperator::Xor => left.op_xor(right),
                        BinaryOperator::Eq => left.op_eq(right),
                        BinaryOperator::Ne => left.op_ne(right),
                        BinaryOperator::Lt => left.op_lt(right),
                        BinaryOperator::Le => left.op_le(right),
                        BinaryOperator::Gt => left.op_gt(right),
                        BinaryOperator::Ge => left.op_ge(right),
                    });
                }
                ExpressionItem::Function { id, num_args } => {
                    let num_args = *num_args as usize;

                    let mut arguments = Variable::array(num_args);
                    for arg_num in 0..num_args {
                        arguments[num_args - arg_num - 1] = stack.pop().unwrap_or_default();
                    }

                    let result = if let Some((_, fnc, _)) = FUNCTIONS.get(*id as usize) {
                        (fnc)(arguments)
                    } else {
                        Box::pin(self.core.eval_fnc(
                            *id - FUNCTIONS.len() as u32,
                            arguments,
                            self.session_id,
                        ))
                        .await?
                    };

                    stack.push(result);
                }
                ExpressionItem::JmpIf { val, pos } => {
                    if stack.last().is_some_and(|v| v.to_bool()) == *val {
                        for _ in 0..*pos {
                            exprs.next();
                        }
                    }
                }
                ExpressionItem::ArrayAccess => {
                    let index = stack
                        .pop()
                        .unwrap_or_default()
                        .to_usize()
                        .unwrap_or_default();
                    let array = stack.pop().unwrap_or_default().into_array();
                    stack.push(array.into_iter().nth(index).unwrap_or_default());
                }
                ExpressionItem::ArrayBuild(num_items) => {
                    let num_items = *num_items as usize;
                    let mut items = Variable::array(num_items);
                    for arg_num in 0..num_items {
                        items[num_items - arg_num - 1] = stack.pop().unwrap_or_default();
                    }
                    stack.push(Variable::Array(items));
                }
                ExpressionItem::Regex(regex) => {
                    self.captures.clear();
                    let value = stack.pop().unwrap_or_default().into_string();

                    if let Some(captures_) = regex.captures(value.as_ref()) {
                        for capture in captures_.iter() {
                            self.captures
                                .push(capture.map_or("", |m| m.as_str()).to_compact_string());
                        }
                    }

                    stack.push(Variable::Integer(!self.captures.is_empty() as i64));
                }
            }
        }

        Ok(stack.pop().unwrap_or_default())
    }
}

impl Expression {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn items(&self) -> &[ExpressionItem] {
        &self.items
    }
}

impl<'x> Variable<'x> {
    pub fn op_add(self, other: Variable<'x>) -> Variable<'x> {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => Variable::Integer(a.saturating_add(b)),
            (Variable::Float(a), Variable::Float(b)) => Variable::Float(a + b),
            (Variable::Integer(i), Variable::Float(f))
            | (Variable::Float(f), Variable::Integer(i)) => Variable::Float(i as f64 + f),
            (Variable::Array(a), Variable::Array(b)) => {
                Variable::Array(a.into_iter().chain(b).collect::<Vec<_>>())
            }
            (Variable::Array(a), b) => {
                Variable::Array(a.into_iter().chain([b]).collect::<Vec<_>>())
            }
            (a, Variable::Array(b)) => {
                Variable::Array([a].into_iter().chain(b).collect::<Vec<_>>())
            }
            (Variable::String(a), b) => {
                if !a.is_empty() {
                    Variable::String(StringCow::Owned(format_compact!("{}{}", a, b)))
                } else {
                    b
                }
            }
            (a, Variable::String(b)) => {
                if !b.is_empty() {
                    Variable::String(StringCow::Owned(format_compact!("{}{}", a, b)))
                } else {
                    a
                }
            }
        }
    }

    pub fn op_subtract(self, other: Variable<'x>) -> Variable<'x> {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => Variable::Integer(a.saturating_sub(b)),
            (Variable::Float(a), Variable::Float(b)) => Variable::Float(a - b),
            (Variable::Integer(a), Variable::Float(b)) => Variable::Float(a as f64 - b),
            (Variable::Float(a), Variable::Integer(b)) => Variable::Float(a - b as f64),
            (Variable::Array(a), b) | (b, Variable::Array(a)) => {
                Variable::Array(a.into_iter().filter(|v| v != &b).collect::<Vec<_>>())
            }
            (a, b) => a.parse_number().op_subtract(b.parse_number()),
        }
    }

    pub fn op_multiply(self, other: Variable<'x>) -> Variable<'x> {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => Variable::Integer(a.saturating_mul(b)),
            (Variable::Float(a), Variable::Float(b)) => Variable::Float(a * b),
            (Variable::Integer(i), Variable::Float(f))
            | (Variable::Float(f), Variable::Integer(i)) => Variable::Float(i as f64 * f),
            (a, b) => a.parse_number().op_multiply(b.parse_number()),
        }
    }

    pub fn op_divide(self, other: Variable<'x>) -> Variable<'x> {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => {
                Variable::Float(if b != 0 { a as f64 / b as f64 } else { 0.0 })
            }
            (Variable::Float(a), Variable::Float(b)) => {
                Variable::Float(if b != 0.0 { a / b } else { 0.0 })
            }
            (Variable::Integer(a), Variable::Float(b)) => {
                Variable::Float(if b != 0.0 { a as f64 / b } else { 0.0 })
            }
            (Variable::Float(a), Variable::Integer(b)) => {
                Variable::Float(if b != 0 { a / b as f64 } else { 0.0 })
            }
            (a, b) => a.parse_number().op_divide(b.parse_number()),
        }
    }

    pub fn op_and(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self.to_bool() & other.to_bool()))
    }

    pub fn op_or(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self.to_bool() | other.to_bool()))
    }

    pub fn op_xor(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self.to_bool() ^ other.to_bool()))
    }

    pub fn op_eq(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self == other))
    }

    pub fn op_ne(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self != other))
    }

    pub fn op_lt(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self < other))
    }

    pub fn op_le(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self <= other))
    }

    pub fn op_gt(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self > other))
    }

    pub fn op_ge(self, other: Variable) -> Variable {
        Variable::Integer(i64::from(self >= other))
    }

    pub fn op_not(self) -> Variable<'static> {
        Variable::Integer(i64::from(!self.to_bool()))
    }

    pub fn op_minus(self) -> Variable<'static> {
        match self {
            Variable::Integer(n) => Variable::Integer(-n),
            Variable::Float(n) => Variable::Float(-n),
            _ => self.parse_number().op_minus(),
        }
    }

    pub fn parse_number(&self) -> Variable<'static> {
        match self {
            Variable::String(s) if !s.is_empty() => {
                if let Ok(n) = s.as_str().parse::<i64>() {
                    Variable::Integer(n)
                } else if let Ok(n) = s.as_str().parse::<f64>() {
                    Variable::Float(n)
                } else {
                    Variable::Integer(0)
                }
            }
            Variable::Integer(n) => Variable::Integer(*n),
            Variable::Float(n) => Variable::Float(*n),
            Variable::Array(l) => Variable::Integer(l.is_empty() as i64),
            _ => Variable::Integer(0),
        }
    }

    #[inline(always)]
    fn array(num_items: usize) -> Vec<Variable<'static>> {
        let mut items = Vec::with_capacity(num_items);
        for _ in 0..num_items {
            items.push(Variable::Integer(0));
        }
        items
    }

    pub fn to_ref<'y: 'x>(&'y self) -> Variable<'x> {
        match self {
            Variable::String(s) => Variable::String(StringCow::Borrowed(s.as_str())),
            Variable::Integer(n) => Variable::Integer(*n),
            Variable::Float(n) => Variable::Float(*n),
            Variable::Array(l) => Variable::Array(l.iter().map(|v| v.to_ref()).collect::<Vec<_>>()),
        }
    }

    pub fn to_bool(&self) -> bool {
        match self {
            Variable::Float(f) => *f != 0.0,
            Variable::Integer(n) => *n != 0,
            Variable::String(s) => !s.is_empty(),
            Variable::Array(a) => !a.is_empty(),
        }
    }

    pub fn to_string(&self) -> StringCow {
        match self {
            Variable::String(s) => StringCow::Borrowed(s.as_str()),
            Variable::Integer(n) => StringCow::Owned(n.to_compact_string()),
            Variable::Float(n) => StringCow::Owned(n.to_compact_string()),
            Variable::Array(l) => {
                let mut result = CompactString::with_capacity(self.len() * 10);
                for item in l {
                    if !result.is_empty() {
                        result.push_str("\r\n");
                    }
                    match item {
                        Variable::String(v) => result.push_str(v.as_str()),
                        Variable::Integer(v) => result.push_str(&v.to_compact_string()),
                        Variable::Float(v) => result.push_str(&v.to_compact_string()),
                        Variable::Array(_) => {}
                    }
                }
                StringCow::Owned(result)
            }
        }
    }

    pub fn into_string(self) -> StringCow<'x> {
        match self {
            Variable::String(s) => s,
            Variable::Integer(n) => StringCow::Owned(n.to_compact_string()),
            Variable::Float(n) => StringCow::Owned(n.to_compact_string()),
            Variable::Array(l) => {
                let mut result = CompactString::with_capacity(l.len() * 10);
                for item in l {
                    if !result.is_empty() {
                        result.push_str("\r\n");
                    }
                    match item {
                        Variable::String(v) => result.push_str(v.as_ref()),
                        Variable::Integer(v) => result.push_str(&v.to_compact_string()),
                        Variable::Float(v) => result.push_str(&v.to_compact_string()),
                        Variable::Array(_) => {}
                    }
                }
                StringCow::Owned(result)
            }
        }
    }

    pub fn to_integer(&self) -> Option<i64> {
        match self {
            Variable::Integer(n) => Some(*n),
            Variable::Float(n) => Some(*n as i64),
            Variable::String(s) if !s.is_empty() => s.as_str().parse::<i64>().ok(),
            _ => None,
        }
    }

    pub fn to_usize(&self) -> Option<usize> {
        match self {
            Variable::Integer(n) => Some(*n as usize),
            Variable::Float(n) => Some(*n as usize),
            Variable::String(s) if !s.is_empty() => s.as_str().parse::<usize>().ok(),
            _ => None,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Variable::String(s) => s.len(),
            Variable::Integer(_) | Variable::Float(_) => 2,
            Variable::Array(l) => l.iter().map(|v| v.len() + 2).sum(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Variable::String(s) => s.is_empty(),
            _ => false,
        }
    }

    pub fn as_array(&self) -> Option<&[Variable]> {
        match self {
            Variable::Array(l) => Some(l),
            _ => None,
        }
    }

    pub fn into_array(self) -> Vec<Variable<'x>> {
        match self {
            Variable::Array(l) => l,
            v if !v.is_empty() => vec![v],
            _ => vec![],
        }
    }

    pub fn to_array(&self) -> Vec<Variable<'_>> {
        match self {
            Variable::Array(l) => l.iter().map(|v| v.to_ref()).collect::<Vec<_>>(),
            v if !v.is_empty() => vec![v.to_ref()],
            _ => vec![],
        }
    }

    pub fn into_owned(self) -> Variable<'static> {
        match self {
            Variable::String(s) => Variable::String(StringCow::Owned(s.into_owned())),
            Variable::Integer(n) => Variable::Integer(n),
            Variable::Float(n) => Variable::Float(n),
            Variable::Array(l) => Variable::Array(l.into_iter().map(|v| v.into_owned()).collect()),
        }
    }
}

impl PartialEq for Variable<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Integer(a), Self::Integer(b)) => a == b,
            (Self::Float(a), Self::Float(b)) => a == b,
            (Self::Integer(a), Self::Float(b)) | (Self::Float(b), Self::Integer(a)) => {
                *a as f64 == *b
            }
            (Self::String(a), Self::String(b)) => a.as_str() == b.as_str(),
            (Self::String(_), Self::Integer(_) | Self::Float(_)) => &self.parse_number() == other,
            (Self::Integer(_) | Self::Float(_), Self::String(_)) => self == &other.parse_number(),
            (Self::Array(a), Self::Array(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Variable<'_> {}

#[allow(clippy::non_canonical_partial_ord_impl)]
impl PartialOrd for Variable<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Integer(a), Self::Integer(b)) => a.partial_cmp(b),
            (Self::Float(a), Self::Float(b)) => a.partial_cmp(b),
            (Self::Integer(a), Self::Float(b)) => (*a as f64).partial_cmp(b),
            (Self::Float(a), Self::Integer(b)) => a.partial_cmp(&(*b as f64)),
            (Self::String(a), Self::String(b)) => a.as_str().partial_cmp(b.as_str()),
            (Self::String(_), Self::Integer(_) | Self::Float(_)) => {
                self.parse_number().partial_cmp(other)
            }
            (Self::Integer(_) | Self::Float(_), Self::String(_)) => {
                self.partial_cmp(&other.parse_number())
            }
            (Self::Array(a), Self::Array(b)) => a.partial_cmp(b),
            (Self::Array(_) | Self::String(_), _) => Ordering::Greater.into(),
            (_, Self::Array(_)) => Ordering::Less.into(),
        }
    }
}

impl Ord for Variable<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Greater)
    }
}

impl Display for Variable<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Variable::String(v) => v.fmt(f),
            Variable::Integer(v) => v.fmt(f),
            Variable::Float(v) => v.fmt(f),
            Variable::Array(v) => {
                for (i, v) in v.iter().enumerate() {
                    if i > 0 {
                        f.write_str("\n")?;
                    }
                    v.fmt(f)?;
                }
                Ok(())
            }
        }
    }
}

impl<'x> From<&'x Constant> for Variable<'x> {
    fn from(value: &'x Constant) -> Self {
        match value {
            Constant::Integer(i) => Variable::Integer(*i),
            Constant::Float(f) => Variable::Float(*f),
            Constant::String(s) => Variable::String(StringCow::Borrowed(s.as_str())),
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for CompactString {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        if let Variable::String(s) = value {
            Ok(match s {
                StringCow::Borrowed(v) => v.into(),
                StringCow::Owned(v) => v,
            })
        } else {
            Err(())
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for String {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        if let Variable::String(s) = value {
            Ok(match s {
                StringCow::Borrowed(v) => v.to_string(),
                StringCow::Owned(v) => v.into_string(),
            })
        } else {
            Err(())
        }
    }
}

impl<'x> From<Variable<'x>> for bool {
    fn from(val: Variable<'x>) -> Self {
        val.to_bool()
    }
}

impl<'x> TryFrom<Variable<'x>> for i64 {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        value.to_integer().ok_or(())
    }
}

impl<'x> TryFrom<Variable<'x>> for u64 {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        value.to_integer().map(|v| v as u64).ok_or(())
    }
}

impl<'x> TryFrom<Variable<'x>> for usize {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        value.to_usize().ok_or(())
    }
}

impl<'x> TryFrom<Variable<'x>> for StatusCode {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value.to_integer() {
            Some(v) => match StatusCode::from_u16(v as u16) {
                Ok(status) => Ok(status),
                Err(_) => Err(()),
            },
            None => Err(()),
        }
    }
}
