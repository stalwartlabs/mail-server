/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

pub mod exec;
pub mod query;

use ahash::AHashMap;
use sieve::{compiler::Number, Compiler, Input, PluginArgument};
use tokio::runtime::Handle;

use crate::core::SMTP;

type RegisterPluginFnc = fn(u32, &mut Compiler) -> ();
type ExecPluginFnc = fn(PluginContext<'_>) -> Input;

pub struct PluginContext<'x> {
    pub span: &'x tracing::Span,
    pub handle: &'x Handle,
    pub core: &'x SMTP,
    pub data: &'x mut AHashMap<String, String>,
    pub arguments: Vec<PluginArgument<String, Number>>,
}

const PLUGINS_EXEC: [ExecPluginFnc; 2] = [query::exec, exec::exec];
const PLUGINS_REGISTER: [RegisterPluginFnc; 2] = [query::register, exec::register];

pub trait RegisterSievePlugins {
    fn register_plugins(self) -> Self;
}

impl RegisterSievePlugins for Compiler {
    fn register_plugins(mut self) -> Self {
        for (i, fnc) in PLUGINS_REGISTER.iter().enumerate() {
            fnc(i as u32, &mut self);
        }
        self
    }
}

impl SMTP {
    pub fn run_plugin_blocking(&self, id: u32, ctx: PluginContext<'_>) -> Input {
        PLUGINS_EXEC
            .get(id as usize)
            .map(|fnc| fnc(ctx))
            .unwrap_or(false.into())
    }
}
