/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use sieve::{runtime::Variable, Envelope};
use store::Value;

use crate::IntoString;

pub mod functions;
pub mod plugins;

#[derive(Debug, serde::Serialize)]
#[serde(tag = "action")]
#[serde(rename_all = "camelCase")]
pub enum ScriptModification {
    SetEnvelope {
        name: Envelope,
        value: String,
    },
    AddHeader {
        name: Arc<String>,
        value: Arc<String>,
    },
}

pub fn into_sieve_value(value: Value) -> Variable {
    match value {
        Value::Integer(v) => Variable::Integer(v),
        Value::Bool(v) => Variable::Integer(i64::from(v)),
        Value::Float(v) => Variable::Float(v),
        Value::Text(v) => Variable::String(v.into_owned().into()),
        Value::Blob(v) => Variable::String(v.into_owned().into_string().into()),
        Value::Null => Variable::default(),
    }
}

pub fn into_store_value(value: Variable) -> Value<'static> {
    match value {
        Variable::String(v) => Value::Text(v.to_string().into()),
        Variable::Integer(v) => Value::Integer(v),
        Variable::Float(v) => Value::Float(v),
        v => Value::Text(v.to_string().into_owned().into()),
    }
}

pub fn to_store_value(value: &Variable) -> Value<'static> {
    match value {
        Variable::String(v) => Value::Text(v.to_string().into()),
        Variable::Integer(v) => Value::Integer(*v),
        Variable::Float(v) => Value::Float(*v),
        v => Value::Text(v.to_string().into_owned().into()),
    }
}
