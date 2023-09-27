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

use sieve::{runtime::Variable, Context};

use crate::config::scripts::SieveContext;

pub fn fn_is_empty<'x>(_: &'x Context<'x, SieveContext>, v: Vec<Variable<'x>>) -> Variable<'x> {
    match &v[0] {
        Variable::String(s) => s.is_empty(),
        Variable::StringRef(s) => s.is_empty(),
        Variable::Integer(_) | Variable::Float(_) => false,
        Variable::Array(a) => a.is_empty(),
        Variable::ArrayRef(a) => a.is_empty(),
    }
    .into()
}

pub fn fn_is_ip_addr<'x>(_: &'x Context<'x, SieveContext>, v: Vec<Variable<'x>>) -> Variable<'x> {
    v[0].to_cow().parse::<std::net::IpAddr>().is_ok().into()
}

pub fn fn_is_var_names<'x>(
    ctx: &'x Context<'x, SieveContext>,
    _: Vec<Variable<'x>>,
) -> Variable<'x> {
    Variable::Array(
        ctx.global_variable_names()
            .map(|v| Variable::from(v.to_string()))
            .collect(),
    )
}
