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

use sieve::{runtime::Variable, Compiler, Input, SetVariable};

use super::PluginContext;

pub fn register(plugin_id: u32, compiler: &mut Compiler) {
    compiler
        .register_plugin("detect_lang")
        .with_id(plugin_id)
        .with_variable_argument()
        .with_string_argument();
}

pub fn exec(ctx: PluginContext<'_>) -> Input {
    let mut arguments = ctx.arguments.into_iter();

    let name = arguments.next().and_then(|a| a.unwrap_variable()).unwrap();
    let text = arguments.next().and_then(|a| a.unwrap_string()).unwrap();

    Input::Variables {
        list: vec![SetVariable {
            name,
            value: Variable::StringRef(
                whatlang::detect_lang(&text)
                    .map(|l| l.code())
                    .unwrap_or("unknown"),
            ),
        }],
    }
}
