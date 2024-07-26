/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod bayes;
pub mod dns;
pub mod exec;
pub mod headers;
pub mod http;
pub mod lookup;
pub mod pyzor;
pub mod query;
pub mod text;

use mail_parser::Message;
use sieve::{runtime::Variable, FunctionMap, Input};

use crate::{config::scripts::ScriptCache, Core};

use super::ScriptModification;

type RegisterPluginFnc = fn(u32, &mut FunctionMap) -> ();

pub struct PluginContext<'x> {
    pub session_id: u64,
    pub core: &'x Core,
    pub cache: &'x ScriptCache,
    pub message: &'x Message<'x>,
    pub modifications: &'x mut Vec<ScriptModification>,
    pub arguments: Vec<Variable>,
}

const PLUGINS_REGISTER: [RegisterPluginFnc; 18] = [
    query::register,
    exec::register,
    lookup::register,
    lookup::register_get,
    lookup::register_set,
    lookup::register_remote,
    lookup::register_local_domain,
    dns::register,
    dns::register_exists,
    http::register_header,
    bayes::register_train,
    bayes::register_untrain,
    bayes::register_classify,
    bayes::register_is_balanced,
    pyzor::register,
    headers::register,
    text::register_tokenize,
    text::register_domain_part,
];

pub trait RegisterSievePlugins {
    fn register_plugins(self) -> Self;
}

impl RegisterSievePlugins for FunctionMap {
    fn register_plugins(mut self) -> Self {
        #[cfg(feature = "test_mode")]
        {
            self.set_external_function("print", PLUGINS_REGISTER.len() as u32, 1)
        }

        for (i, fnc) in PLUGINS_REGISTER.iter().enumerate() {
            fnc(i as u32, &mut self);
        }
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
            5 => lookup::exec_remote(ctx).await,
            6 => lookup::exec_local_domain(ctx).await,
            7 => dns::exec(ctx).await,
            8 => dns::exec_exists(ctx).await,
            9 => http::exec_header(ctx).await,
            10 => bayes::exec_train(ctx).await,
            11 => bayes::exec_untrain(ctx).await,
            12 => bayes::exec_classify(ctx).await,
            13 => bayes::exec_is_balanced(ctx).await,
            14 => pyzor::exec(ctx).await,
            15 => headers::exec(ctx),
            16 => text::exec_tokenize(ctx),
            17 => text::exec_domain_part(ctx),
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
