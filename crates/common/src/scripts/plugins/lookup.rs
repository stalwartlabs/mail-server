/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::PluginContext;
use crate::scripts::into_sieve_value;
use sieve::{FunctionMap, runtime::Variable};
use store::{Deserialize, Value, dispatch::lookup::KeyValue};

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("key_exists", plugin_id, 2);
}

pub fn register_get(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("key_get", plugin_id, 2);
}

pub fn register_set(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("key_set", plugin_id, 4);
}

pub fn register_local_domain(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("is_local_domain", plugin_id, 2);
}

pub async fn exec(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.server.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.server.core.storage.lookup),
    }
    .ok_or_else(|| {
        trc::SieveEvent::RuntimeError
            .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
            .details("Unknown store")
    })?;

    Ok(match &ctx.arguments[1] {
        Variable::Array(items) => {
            for item in items.iter() {
                if !item.is_empty() && store.key_exists(item.to_string()).await? {
                    return Ok(true.into());
                }
            }
            false
        }
        v if !v.is_empty() => store.key_exists(v.to_string()).await?,
        _ => false,
    }
    .into())
}

pub async fn exec_get(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.server.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.server.core.storage.lookup),
    }
    .ok_or_else(|| {
        trc::SieveEvent::RuntimeError
            .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
            .details("Unknown store")
    })?
    .key_get::<VariableWrapper>(ctx.arguments[1].to_string())
    .await
    .map(|v| v.map(|v| v.into_inner()).unwrap_or_default())
}

pub async fn exec_set(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let expires = match &ctx.arguments[3] {
        Variable::Integer(v) => Some(*v as u64),
        Variable::Float(v) => Some(*v as u64),
        _ => None,
    };

    match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.server.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.server.core.storage.lookup),
    }
    .ok_or_else(|| {
        trc::SieveEvent::RuntimeError
            .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
            .details("Unknown store")
    })?
    .key_set(
        KeyValue::new(
            ctx.arguments[1].to_string().into_owned().into_bytes(),
            if !ctx.arguments[2].is_empty() {
                bincode::serde::encode_to_vec(&ctx.arguments[2], bincode::config::standard())
                    .unwrap_or_default()
            } else {
                vec![]
            },
        )
        .expires_opt(expires),
    )
    .await
    .map(|_| true.into())
}

pub async fn exec_local_domain(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let domain = ctx.arguments[1].to_string();

    if !domain.is_empty() {
        return match &ctx.arguments[0] {
            Variable::String(v) if !v.is_empty() => {
                ctx.server.core.storage.directories.get(v.as_ref())
            }
            _ => Some(&ctx.server.core.storage.directory),
        }
        .ok_or_else(|| {
            trc::SieveEvent::RuntimeError
                .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
                .details("Unknown directory")
        })?
        .is_local_domain(domain.as_ref())
        .await
        .map(Into::into);
    }

    Ok(Variable::default())
}

#[derive(Debug, PartialEq, Eq)]
pub struct VariableWrapper(Variable);

impl Deserialize for VariableWrapper {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(VariableWrapper(
            bincode::serde::decode_from_slice::<Variable, _>(bytes, bincode::config::standard())
                .map(|v| v.0)
                .unwrap_or_else(|_| {
                    Variable::String(String::from_utf8_lossy(bytes).into_owned().into())
                }),
        ))
    }
}

impl From<i64> for VariableWrapper {
    fn from(value: i64) -> Self {
        VariableWrapper(value.into())
    }
}

impl VariableWrapper {
    pub fn into_inner(self) -> Variable {
        self.0
    }
}

impl From<Value<'static>> for VariableWrapper {
    fn from(value: Value<'static>) -> Self {
        VariableWrapper(into_sieve_value(value))
    }
}
