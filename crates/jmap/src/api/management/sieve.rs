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

use std::time::SystemTime;

use hyper::Method;
use jmap_proto::error::request::RequestError;
use serde_json::json;
use sieve::{runtime::Variable, Envelope};
use smtp::scripts::ScriptParameters;
use utils::url_params::UrlParams;

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    JMAP,
};

impl JMAP {
    pub async fn handle_run_sieve(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
    ) -> HttpResponse {
        let script = match (
            path.get(1)
                .and_then(|name| self.core.sieve.scripts.get(*name))
                .cloned(),
            req.method(),
        ) {
            (Some(script), &Method::POST) => script,
            _ => {
                return RequestError::not_found().into_http_response();
            }
        };

        let mut params = ScriptParameters::new()
            .set_variable(
                "now",
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            )
            .set_variable("test", true)
            .with_message(body.as_deref().unwrap_or_default());

        let mut envelope_to = Vec::new();
        for (key, value) in UrlParams::new(req.uri().query()).into_inner() {
            let env = match key.as_ref() {
                "env_to" => {
                    envelope_to.push(Variable::from(value.to_lowercase()));
                    continue;
                }
                "env_from" => Envelope::From,
                "env_orcpt" => Envelope::Orcpt,
                "env_ret" => Envelope::Ret,
                "env_notify" => Envelope::Notify,
                "env_id" => Envelope::Envid,
                "env_bym" => Envelope::ByMode,
                "env_byt" => Envelope::ByTrace,
                "env_byta" => Envelope::ByTimeAbsolute,
                "env_bytr" => Envelope::ByTimeRelative,
                _ => {
                    params = params.set_variable(key.into_owned(), value.into_owned());
                    continue;
                }
            };

            params = params.set_envelope(env, value);
        }

        if !envelope_to.is_empty() {
            params = params.set_envelope(Envelope::To, Variable::from(envelope_to));
        }

        // Run script
        let result = self
            .smtp
            .run_script(script, params, tracing::debug_span!("sieve_manual_run"))
            .await;

        JsonResponse::new(json!({
            "data": result,
        }))
        .into_http_response()
    }
}
