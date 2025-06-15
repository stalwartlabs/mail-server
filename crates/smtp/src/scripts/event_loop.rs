/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, future::Future, sync::Arc, time::Instant};

use common::{Server, scripts::plugins::PluginContext};

use mail_auth::common::headers::HeaderWriter;
use mail_parser::{Encoding, Message, MessagePart, PartType};
use sieve::{
    Event, Input, MatchAs, Recipient, Sieve,
    compiler::grammar::actions::action_redirect::{ByMode, ByTime, Notify, NotifyItem, Ret},
};
use smtp_proto::{
    MAIL_BY_TRACE, MAIL_RET_FULL, MAIL_RET_HDRS, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE,
    RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};
use trc::SieveEvent;

use crate::{
    inbound::DkimSign,
    queue::{DomainPart, MessageSource, quota::HasQueueQuota, spool::SmtpSpool},
};

use super::{ScriptModification, ScriptParameters, ScriptResult};

pub trait RunScript: Sync + Send {
    fn run_script(
        &self,
        script_id: String,
        script: Arc<Sieve>,
        params: ScriptParameters<'_>,
    ) -> impl Future<Output = ScriptResult> + Send;
}

impl RunScript for Server {
    async fn run_script(
        &self,
        script_id: String,
        script: Arc<Sieve>,
        params: ScriptParameters<'_>,
    ) -> ScriptResult {
        // Create filter instance
        let time = Instant::now();
        let mut instance = self
            .core
            .sieve
            .trusted_runtime
            .filter_parsed(params.message.unwrap_or_else(|| Message {
                parts: vec![MessagePart {
                    headers: vec![],
                    is_encoding_problem: false,
                    body: PartType::Text("".into()),
                    encoding: Encoding::None,
                    offset_header: 0,
                    offset_body: 0,
                    offset_end: 0,
                }],
                raw_message: b""[..].into(),
                ..Default::default()
            }))
            .with_vars_env(params.variables)
            .with_envelope_list(params.envelope)
            .with_user_address(&params.from_addr)
            .with_user_full_name(&params.from_name);
        let mut input = Input::script("__script", script);
        let mut messages: Vec<Vec<u8>> = Vec::new();
        let session_id = params.session_id;

        let mut reject_reason = None;
        let mut modifications = vec![];
        let mut keep_id = usize::MAX;

        // Start event loop
        while let Some(result) = instance.run(input) {
            match result {
                Ok(event) => match event {
                    Event::IncludeScript { name, optional } => {
                        let name_ = name.as_str().to_lowercase();
                        if let Some(script) = self.core.sieve.trusted_scripts.get(&name_) {
                            input = Input::script(name, script.clone());
                        } else if optional {
                            input = false.into();
                        } else {
                            trc::event!(
                                Sieve(SieveEvent::ScriptNotFound),
                                Id = script_id.clone(),
                                SpanId = session_id,
                                Details = name_,
                            );
                            break;
                        }
                    }
                    Event::ListContains {
                        lists,
                        values,
                        match_as,
                    } => {
                        input = false.into();
                        'outer: for list in lists {
                            if let Some(store) = self.core.storage.lookups.get(&list) {
                                for value in &values {
                                    if let Ok(true) = store
                                        .key_exists(if !matches!(match_as, MatchAs::Lowercase) {
                                            value.clone()
                                        } else {
                                            value.to_lowercase()
                                        })
                                        .await
                                    {
                                        input = true.into();
                                        break 'outer;
                                    }
                                }
                            } else {
                                trc::event!(
                                    Sieve(SieveEvent::ListNotFound),
                                    Id = script_id.clone(),
                                    SpanId = session_id,
                                    Details = list,
                                );
                            }
                        }
                    }
                    Event::Function { id, arguments } => {
                        input = self
                            .core
                            .run_plugin(
                                id,
                                PluginContext {
                                    session_id,
                                    server: self,
                                    message: instance.message(),
                                    modifications: &mut modifications,
                                    access_token: params.access_token,
                                    arguments,
                                },
                            )
                            .await;
                    }
                    Event::Keep { message_id, .. } => {
                        keep_id = message_id;
                        input = true.into();
                    }
                    Event::Discard => {
                        keep_id = usize::MAX - 1;
                        input = true.into();
                    }
                    Event::Reject { reason, .. } => {
                        reject_reason = reason.into();
                        input = true.into();
                    }
                    Event::SendMessage {
                        recipient,
                        notify,
                        return_of_content,
                        by_time,
                        message_id,
                    } => {
                        // Build message
                        let return_path_lcase = params.return_path.to_lowercase();
                        let return_path_domain = return_path_lcase.domain_part().to_string();
                        let mut message = self.new_message(
                            params.return_path.clone(),
                            return_path_lcase,
                            return_path_domain,
                            session_id,
                        );
                        match recipient {
                            Recipient::Address(rcpt) => {
                                message.add_recipient(rcpt, self).await;
                            }
                            Recipient::Group(rcpt_list) => {
                                for rcpt in rcpt_list {
                                    message.add_recipient(rcpt, self).await;
                                }
                            }
                            Recipient::List(list) => {
                                trc::event!(
                                    Sieve(SieveEvent::NotSupported),
                                    Id = script_id.clone(),
                                    SpanId = session_id,
                                    Details = list,
                                    Reason = "Sending to lists is not supported.",
                                );
                            }
                        }

                        // Set notify flags
                        let mut flags = 0;
                        match notify {
                            Notify::Never => {
                                flags = RCPT_NOTIFY_NEVER;
                            }
                            Notify::Items(items) => {
                                for item in items {
                                    flags |= match item {
                                        NotifyItem::Success => RCPT_NOTIFY_SUCCESS,
                                        NotifyItem::Failure => RCPT_NOTIFY_FAILURE,
                                        NotifyItem::Delay => RCPT_NOTIFY_DELAY,
                                    };
                                }
                            }
                            Notify::Default => (),
                        }
                        if flags > 0 {
                            for rcpt in &mut message.recipients {
                                rcpt.flags |= flags;
                            }
                        }

                        // Set ByTime flags
                        match by_time {
                            ByTime::Relative {
                                rlimit,
                                mode,
                                trace,
                            } => {
                                if trace {
                                    message.flags |= MAIL_BY_TRACE;
                                }
                                match mode {
                                    ByMode::Notify => {
                                        for domain in &mut message.domains {
                                            domain.notify.due += rlimit;
                                        }
                                    }
                                    ByMode::Return => {
                                        for domain in &mut message.domains {
                                            domain.notify.due += rlimit;
                                        }
                                    }
                                    ByMode::Default => (),
                                }
                            }
                            ByTime::Absolute {
                                alimit,
                                mode,
                                trace,
                            } => {
                                if trace {
                                    message.flags |= MAIL_BY_TRACE;
                                }
                                match mode {
                                    ByMode::Notify => {
                                        for domain in &mut message.domains {
                                            domain.notify.due = alimit as u64;
                                        }
                                    }
                                    ByMode::Return => {
                                        for domain in &mut message.domains {
                                            domain.expires = alimit as u64;
                                        }
                                    }
                                    ByMode::Default => (),
                                }
                            }
                            ByTime::None => (),
                        };

                        // Set ret
                        match return_of_content {
                            Ret::Full => {
                                message.flags |= MAIL_RET_FULL;
                            }
                            Ret::Hdrs => {
                                message.flags |= MAIL_RET_HDRS;
                            }
                            Ret::Default => (),
                        }

                        // Queue message
                        let is_forward = message_id == 0;
                        let raw_message = if !is_forward {
                            messages.get(message_id - 1).map(|m| m.as_slice())
                        } else {
                            instance.message().raw_message().into()
                        };
                        if let Some(raw_message) = raw_message.filter(|m| !m.is_empty()) {
                            let headers = if !params.sign.is_empty() {
                                let mut headers = Vec::new();

                                for dkim in &params.sign {
                                    if let Some(dkim) = self.get_dkim_signer(dkim, session_id) {
                                        match dkim.sign(raw_message) {
                                            Ok(signature) => {
                                                signature.write_header(&mut headers);
                                            }
                                            Err(err) => {
                                                trc::error!(
                                                    trc::Error::from(err)
                                                        .span_id(session_id)
                                                        .caused_by(trc::location!())
                                                        .details("DKIM sign failed")
                                                );
                                            }
                                        }
                                    }
                                }

                                if is_forward {
                                    headers.extend_from_slice(params.headers.unwrap_or_default());
                                }

                                Some(Cow::Owned(headers))
                            } else if is_forward {
                                params.headers.map(Cow::Borrowed)
                            } else {
                                None
                            };

                            if self.has_quota(&mut message).await {
                                message
                                    .queue(
                                        headers.as_deref(),
                                        raw_message,
                                        session_id,
                                        self,
                                        MessageSource::Autogenerated,
                                    )
                                    .await;
                            } else {
                                trc::event!(
                                    Sieve(SieveEvent::QuotaExceeded),
                                    SpanId = session_id,
                                    Id = script_id.clone(),
                                    From = message.return_path_lcase,
                                    To = message
                                        .recipients
                                        .into_iter()
                                        .map(|r| trc::Value::from(r.address_lcase))
                                        .collect::<Vec<_>>(),
                                );
                            }
                        }

                        input = true.into();
                    }
                    Event::CreatedMessage { message, .. } => {
                        messages.push(message);
                        input = true.into();
                    }
                    Event::SetEnvelope { envelope, value } => {
                        modifications.push(ScriptModification::SetEnvelope {
                            name: envelope,
                            value,
                        });
                        input = true.into();
                    }
                    unsupported => {
                        trc::event!(
                            Sieve(SieveEvent::NotSupported),
                            Id = script_id.clone(),
                            SpanId = session_id,
                            Reason = "Unsupported event",
                            Details = format!("{unsupported:?}"),
                        );
                        break;
                    }
                },
                Err(err) => {
                    trc::event!(
                        Sieve(SieveEvent::RuntimeError),
                        Id = script_id.clone(),
                        SpanId = session_id,
                        Reason = err.to_string(),
                    );
                    break;
                }
            }
        }

        // Keep id
        // 0 = use original message
        // MAX = implicit keep
        // MAX - 1 = discard message

        if keep_id == 0 {
            trc::event!(
                Sieve(SieveEvent::ActionAccept),
                SpanId = session_id,
                Id = script_id,
                Elapsed = time.elapsed(),
            );

            ScriptResult::Accept { modifications }
        } else if let Some(mut reject_reason) = reject_reason {
            trc::event!(
                Sieve(SieveEvent::ActionReject),
                Id = script_id,
                SpanId = session_id,
                Details = reject_reason.clone(),
                Elapsed = time.elapsed(),
            );

            if !reject_reason.ends_with('\n') {
                reject_reason.push_str("\r\n");
            }
            let mut reject_bytes = reject_reason.as_bytes().iter();
            if matches!(reject_bytes.next(), Some(ch) if ch.is_ascii_digit())
                && matches!(reject_bytes.next(), Some(ch) if ch.is_ascii_digit())
                && matches!(reject_bytes.next(), Some(ch) if ch.is_ascii_digit())
                && matches!(reject_bytes.next(), Some(ch) if ch == &b' ' )
            {
                ScriptResult::Reject(reject_reason)
            } else {
                ScriptResult::Reject(format!("503 5.5.3 {reject_reason}"))
            }
        } else if keep_id != usize::MAX - 1 {
            if let Some(message) = messages.into_iter().nth(keep_id - 1) {
                trc::event!(
                    Sieve(SieveEvent::ActionAccept),
                    SpanId = session_id,
                    Id = script_id,
                    Elapsed = time.elapsed(),
                );

                ScriptResult::Replace {
                    message,
                    modifications,
                }
            } else {
                trc::event!(
                    Sieve(SieveEvent::ActionAcceptReplace),
                    SpanId = session_id,
                    Id = script_id,
                    Elapsed = time.elapsed(),
                );

                ScriptResult::Accept { modifications }
            }
        } else {
            trc::event!(
                Sieve(SieveEvent::ActionDiscard),
                SpanId = session_id,
                Id = script_id,
                Elapsed = time.elapsed()
            );

            ScriptResult::Discard
        }
    }
}
