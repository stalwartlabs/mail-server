/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use ahash::AHashMap;
use common::{
    config::smtp::session::{MTAHook, Stage},
    listener::SessionStream,
    DAEMON_NAME,
};
use mail_auth::AuthenticatedMessage;
use trc::MtaHookEvent;

use crate::{
    core::Session,
    inbound::{
        hooks::{
            Address, Client, Context, Envelope, Message, Protocol, Request, Sasl, Server, Tls,
        },
        milter::Modification,
        FilterResponse,
    },
    queue::QueueId,
};

use super::{client::send_mta_hook_request, Action, Queue, Response};

impl<T: SessionStream> Session<T> {
    pub async fn run_mta_hooks(
        &self,
        stage: Stage,
        message: Option<&AuthenticatedMessage<'_>>,
        queue_id: Option<QueueId>,
    ) -> Result<Vec<Modification>, FilterResponse> {
        let mta_hooks = &self.core.core.smtp.session.hooks;
        if mta_hooks.is_empty() {
            return Ok(Vec::new());
        }

        let mut modifications = Vec::new();
        for mta_hook in mta_hooks {
            if !mta_hook.run_on_stage.contains(&stage)
                || !self
                    .core
                    .core
                    .eval_if(&mta_hook.enable, self, self.data.session_id)
                    .await
                    .unwrap_or(false)
            {
                continue;
            }

            let time = Instant::now();
            match self.run_mta_hook(stage, mta_hook, message, queue_id).await {
                Ok(response) => {
                    trc::event!(
                        MtaHook(match response.action {
                            Action::Accept => MtaHookEvent::ActionAccept,
                            Action::Discard => MtaHookEvent::ActionDiscard,
                            Action::Reject => MtaHookEvent::ActionReject,
                            Action::Quarantine => MtaHookEvent::ActionQuarantine,
                        }),
                        SpanId = self.data.session_id,
                        Id = mta_hook.id.clone(),
                        Elapsed = time.elapsed(),
                    );

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
                    trc::event!(
                        MtaHook(MtaHookEvent::Error),
                        SpanId = self.data.session_id,
                        Id = mta_hook.id.clone(),
                        Reason = err,
                        Elapsed = time.elapsed(),
                    );

                    if mta_hook.tempfail_on_error {
                        return Err(FilterResponse::server_failure());
                    }
                }
            }
        }

        Ok(modifications)
    }

    pub async fn run_mta_hook(
        &self,
        stage: Stage,
        mta_hook: &MTAHook,
        message: Option<&AuthenticatedMessage<'_>>,
        queue_id: Option<QueueId>,
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
                queue: queue_id.map(|id| Queue {
                    id: format!("{:x}", id),
                }),
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

        send_mta_hook_request(mta_hook, request).await
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
