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

use ahash::AHashMap;
use common::{
    config::smtp::session::{FilterHook, Stage},
    listener::SessionStream,
    DAEMON_NAME,
};
use mail_auth::AuthenticatedMessage;

use crate::{
    core::Session,
    inbound::{
        hooks::{
            Address, Client, Context, Envelope, Message, Protocol, Request, Sasl, Server, Tls,
        },
        milter::Modification,
        FilterResponse,
    },
};

use super::{client::send_filter_hook_request, Action, Response};

impl<T: SessionStream> Session<T> {
    pub async fn run_filter_hooks(
        &self,
        stage: Stage,
        message: Option<&AuthenticatedMessage<'_>>,
    ) -> Result<Vec<Modification>, FilterResponse> {
        let filter_hooks = &self.core.core.smtp.session.hooks;
        if filter_hooks.is_empty() {
            return Ok(Vec::new());
        }

        let mut modifications = Vec::new();
        for filter_hook in filter_hooks {
            if !filter_hook.run_on_stage.contains(&stage)
                || !self
                    .core
                    .core
                    .eval_if(&filter_hook.enable, self)
                    .await
                    .unwrap_or(false)
            {
                continue;
            }

            match self.run_filter_hook(stage, filter_hook, message).await {
                Ok(response) => {
                    let mut new_modifications = Vec::with_capacity(response.modifications.len());
                    for modification in response.modifications {
                        new_modifications.push(match modification {
                            super::Modification::ChangeFrom { value, parameters } => {
                                Modification::ChangeFrom {
                                    sender: value,
                                    args: flatten_parameters(parameters),
                                }
                            }
                            super::Modification::AddRecipient { value, parameters } => {
                                Modification::AddRcpt {
                                    recipient: value,
                                    args: flatten_parameters(parameters),
                                }
                            }
                            super::Modification::DeleteRecipient { value } => {
                                Modification::DeleteRcpt { recipient: value }
                            }
                            super::Modification::ReplaceContents { value } => {
                                Modification::ReplaceBody {
                                    value: value.into_bytes(),
                                }
                            }
                            super::Modification::AddHeader { name, value } => {
                                Modification::AddHeader { name, value }
                            }
                            super::Modification::InsertHeader { index, name, value } => {
                                Modification::InsertHeader { index, name, value }
                            }
                            super::Modification::ChangeHeader { index, name, value } => {
                                Modification::ChangeHeader { index, name, value }
                            }
                            super::Modification::DeleteHeader { index, name } => {
                                Modification::ChangeHeader {
                                    index,
                                    name,
                                    value: String::new(),
                                }
                            }
                        });
                    }

                    if !modifications.is_empty() {
                        // The message body can only be replaced once, so we need to remove
                        // any previous replacements.
                        if new_modifications
                            .iter()
                            .any(|m| matches!(m, Modification::ReplaceBody { .. }))
                        {
                            modifications
                                .retain(|m| !matches!(m, Modification::ReplaceBody { .. }));
                        }
                        modifications.extend(new_modifications);
                    } else {
                        modifications = new_modifications;
                    }

                    let mut message = match response.action {
                        Action::Accept => continue,
                        Action::Discard => FilterResponse::accept(),
                        Action::Reject => FilterResponse::reject(),
                        Action::Quarantine => {
                            modifications.push(Modification::AddHeader {
                                name: "X-Quarantine".to_string(),
                                value: "true".to_string(),
                            });
                            FilterResponse::accept()
                        }
                    };

                    if let Some(response) = response.response {
                        if let (Some(status), Some(text)) = (response.status, response.message) {
                            if let Some(enhanced) = response.enhanced_status {
                                message.message = format!("{status} {enhanced} {text}\r\n").into();
                            } else {
                                message.message = format!("{status} {text}\r\n").into();
                            }
                        }
                        message.disconnect = response.disconnect;
                    }

                    return Err(message);
                }
                Err(err) => {
                    tracing::warn!(
                        parent: &self.span,
                        filter_hook.url = &filter_hook.url,
                        context = "filter_hook",
                        event = "error",
                        reason = ?err,
                        "FilterHook filter failed");
                    if filter_hook.tempfail_on_error {
                        return Err(FilterResponse::server_failure());
                    }
                }
            }
        }

        Ok(modifications)
    }

    pub async fn run_filter_hook(
        &self,
        stage: Stage,
        filter_hook: &FilterHook,
        message: Option<&AuthenticatedMessage<'_>>,
    ) -> Result<Response, String> {
        // Build request
        let (tls_version, tls_cipher) = self.stream.tls_version_and_cipher();
        let request = Request {
            context: Context {
                stage: stage.into(),
                client: Client {
                    ip: self.data.remote_ip.to_string(),
                    port: self.data.remote_port,
                    ptr: self
                        .data
                        .iprev
                        .as_ref()
                        .and_then(|ip_rev| ip_rev.ptr.as_ref())
                        .and_then(|ptrs| ptrs.first())
                        .cloned(),
                    helo: (!self.data.helo_domain.is_empty())
                        .then(|| self.data.helo_domain.clone()),
                    active_connections: 1,
                },
                sasl: (!self.data.authenticated_as.is_empty()).then(|| Sasl {
                    login: self.data.authenticated_as.clone(),
                    method: None,
                }),
                tls: (!tls_version.is_empty()).then(|| Tls {
                    version: tls_version.to_string(),
                    cipher: tls_cipher.to_string(),
                    bits: None,
                    issuer: None,
                    subject: None,
                }),
                server: Server {
                    name: DAEMON_NAME.to_string().into(),
                    port: self.data.local_port,
                    ip: self.data.local_ip.to_string().into(),
                },
                queue: None,
                protocol: Protocol { version: 1 },
            },
            envelope: self.data.mail_from.as_ref().map(|from| Envelope {
                from: Address {
                    address: from.address_lcase.clone(),
                    parameters: None,
                },
                to: self
                    .data
                    .rcpt_to
                    .iter()
                    .map(|to| Address {
                        address: to.address_lcase.clone(),
                        parameters: None,
                    })
                    .collect(),
            }),
            message: message.map(|message| Message {
                headers: message
                    .raw_parsed_headers()
                    .iter()
                    .map(|(k, v)| {
                        (
                            String::from_utf8_lossy(k).into_owned(),
                            String::from_utf8_lossy(v).into_owned(),
                        )
                    })
                    .collect(),
                server_headers: vec![],
                contents: String::from_utf8_lossy(message.raw_body()).into_owned(),
                size: message.raw_message().len(),
            }),
        };

        send_filter_hook_request(filter_hook, request).await
    }
}

fn flatten_parameters(parameters: AHashMap<String, Option<String>>) -> String {
    let mut arguments = String::new();
    for (key, value) in parameters {
        if !arguments.is_empty() {
            arguments.push(' ');
        }
        arguments.push_str(key.as_str());
        if let Some(value) = value {
            arguments.push('=');
            arguments.push_str(value.as_str());
        }
    }

    arguments
}
