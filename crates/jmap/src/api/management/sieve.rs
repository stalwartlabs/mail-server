/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::SystemTime;

use common::{scripts::ScriptModification, IntoString};
use hyper::Method;
use jmap_proto::error::request::RequestError;
use serde_json::json;
use sieve::{runtime::Variable, Envelope};
use smtp::scripts::{ScriptParameters, ScriptResult};
use utils::url_params::UrlParams;

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    JMAP,
};

#[derive(Debug, serde::Serialize)]
#[serde(tag = "action")]
#[serde(rename_all = "lowercase")]
pub enum Response {
    Accept {
        modifications: Vec<ScriptModification>,
    },
    Replace {
        message: String,
        modifications: Vec<ScriptModification>,
    },
    Reject {
        reason: String,
    },
    Discard,
}

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
            if key.starts_with("env_to") {
                envelope_to.push(Variable::from(value.to_lowercase()));
                continue;
            }
            let env = match key.as_ref() {
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
        let result = match self
            .smtp
            .run_script(script, params, tracing::debug_span!("sieve_manual_run"))
            .await
        {
            ScriptResult::Accept { modifications } => Response::Accept { modifications },
            ScriptResult::Replace {
                message,
                modifications,
            } => Response::Replace {
                message: message.into_string(),
                modifications,
            },
            ScriptResult::Reject(reason) => Response::Reject { reason },
            ScriptResult::Discard => Response::Discard,
        };

        JsonResponse::new(json!({
            "data": result,
        }))
        .into_http_response()
    }
}
