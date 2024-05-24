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

use std::time::Duration;

use reqwest::redirect::Policy;
use sieve::{runtime::Variable, FunctionMap};

use super::PluginContext;

pub fn register_header(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("http_header", plugin_id, 4);
}

pub async fn exec_header(ctx: PluginContext<'_>) -> Variable {
    let url = ctx.arguments[0].to_string();
    let header = ctx.arguments[1].to_string();
    let agent = ctx.arguments[2].to_string();
    let timeout = ctx.arguments[3].to_string().parse::<u64>().unwrap_or(5000);

    #[cfg(feature = "test_mode")]
    if url.contains("redirect.") {
        return Variable::from(url.split_once("/?").unwrap().1.to_string());
    }

    if let Ok(client) = reqwest::Client::builder()
        .user_agent(agent.as_ref())
        .timeout(Duration::from_millis(timeout))
        .redirect(Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
    {
        client
            .get(url.as_ref())
            .send()
            .await
            .ok()
            .and_then(|response| {
                response
                    .headers()
                    .get(header.as_ref())
                    .and_then(|h| h.to_str().ok())
                    .map(|h| Variable::from(h.to_string()))
            })
            .unwrap_or_default()
    } else {
        false.into()
    }
}
