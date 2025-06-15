/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod dns;
pub mod exec;
pub mod headers;
pub mod http;
pub mod llm_prompt;
pub mod lookup;
pub mod query;
pub mod text;

use mail_parser::Message;
use sieve::{FunctionMap, Input, runtime::Variable};

use crate::{Core, Server, auth::AccessToken};

use super::ScriptModification;

type RegisterPluginFnc = fn(u32, &mut FunctionMap) -> ();

pub struct PluginContext<'x> {
    pub session_id: u64,
    pub access_token: Option<&'x AccessToken>,
    pub server: &'x Server,
    pub message: &'x Message<'x>,
    pub modifications: &'x mut Vec<ScriptModification>,
    pub arguments: Vec<Variable>,
}

const PLUGINS_REGISTER: [RegisterPluginFnc; 13] = [
    query::register,
    exec::register,
    lookup::register,
    lookup::register_get,
    lookup::register_set,
    lookup::register_local_domain,
    dns::register,
    dns::register_exists,
    http::register_header,
    headers::register,
    text::register_tokenize,
    text::register_domain_part,
    llm_prompt::register,
];

pub trait RegisterSievePlugins {
    fn register_plugins_trusted(self) -> Self;
    fn register_plugins_untrusted(self) -> Self;
}

impl RegisterSievePlugins for FunctionMap {
    fn register_plugins_trusted(mut self) -> Self {
        #[cfg(feature = "test_mode")]
        {
            self.set_external_function("print", PLUGINS_REGISTER.len() as u32, 1)
        }

        for (i, fnc) in PLUGINS_REGISTER.iter().enumerate() {
            fnc(i as u32, &mut self);
        }
        self
    }

    fn register_plugins_untrusted(mut self) -> Self {
        llm_prompt::register(12, &mut self);
        self
    }
}

impl Core {
    pub async fn run_plugin(&self, id: u32, ctx: PluginContext<'_>) -> Input {
        #[cfg(feature = "test_mode")]
        if id == PLUGINS_REGISTER.len() as u32 {
            return test_print(ctx);
        }

        let session_id = ctx.session_id;
        let result = match id {
            0 => query::exec(ctx).await,
            1 => exec::exec(ctx).await,
            2 => lookup::exec(ctx).await,
            3 => lookup::exec_get(ctx).await,
            4 => lookup::exec_set(ctx).await,
            5 => lookup::exec_local_domain(ctx).await,
            6 => dns::exec(ctx).await,
            7 => dns::exec_exists(ctx).await,
            8 => http::exec_header(ctx).await,
            9 => headers::exec(ctx),
            10 => text::exec_tokenize(ctx),
            11 => text::exec_domain_part(ctx),
            12 => llm_prompt::exec(ctx).await,
            _ => unreachable!(),
        };

        match result {
            Ok(result) => result.into(),
            Err(err) => {
                trc::error!(err.span_id(session_id).details("Sieve runtime error"));
                Input::FncResult(Variable::default())
            }
        }
    }
}

#[cfg(feature = "test_mode")]
pub fn test_print(ctx: PluginContext<'_>) -> Input {
    println!("{}", ctx.arguments[0].to_string());
    Input::True
}
