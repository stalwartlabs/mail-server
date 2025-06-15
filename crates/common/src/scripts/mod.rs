/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use sieve::{Envelope, runtime::Variable};
use store::Value;
use unicode_security::mixed_script::AugmentedScriptSet;

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

pub trait IsMixedCharset {
    fn is_mixed_charset(&self) -> bool;
}

impl<T: AsRef<str>> IsMixedCharset for T {
    fn is_mixed_charset(&self) -> bool {
        let mut set: Option<AugmentedScriptSet> = None;

        for ch in self.as_ref().chars() {
            if !ch.is_ascii() {
                set.get_or_insert_default().intersect_with(ch.into());
            }
        }

        set.is_some_and(|set| set.is_empty())
    }
}
