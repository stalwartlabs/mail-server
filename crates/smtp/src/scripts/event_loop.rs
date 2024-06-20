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

use std::{borrow::Cow, sync::Arc};

use common::scripts::plugins::PluginContext;
use mail_auth::common::headers::HeaderWriter;
use sieve::{
    compiler::grammar::actions::action_redirect::{ByMode, ByTime, Notify, NotifyItem, Ret},
    Event, Input, MatchAs, Recipient, Sieve,
};
use smtp_proto::{
    MAIL_BY_TRACE, MAIL_RET_FULL, MAIL_RET_HDRS, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE,
    RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};

use crate::{core::SMTP, inbound::DkimSign, queue::DomainPart};

use super::{ScriptModification, ScriptParameters, ScriptResult};

impl SMTP {
    pub async fn run_script(
        &self,
        script: Arc<Sieve>,
        params: ScriptParameters<'_>,
        span: tracing::Span,
    ) -> ScriptResult {
        // Create filter instance
        let mut instance = self
            .core
            .sieve
            .trusted_runtime
            .filter(params.message.unwrap_or_default())
            .with_vars_env(params.variables)
            .with_envelope_list(params.envelope)
            .with_user_address(&params.from_addr)
            .with_user_full_name(&params.from_name);
        let mut input = Input::script("__script", script);
        let mut messages: Vec<Vec<u8>> = Vec::new();

        let mut reject_reason = None;
        let mut modifications = vec![];
        let mut keep_id = usize::MAX;

        // Start event loop
        while let Some(result) = instance.run(input) {
            match result {
                Ok(event) => match event {
                    Event::IncludeScript { name, optional } => {
                        if let Some(script) = self.core.sieve.scripts.get(name.as_str()) {
                            input = Input::script(name, script.clone());
                        } else if optional {
                            input = false.into();
                        } else {
                            tracing::warn!(
                                parent: &span,
                                context = "sieve",
                                event = "script-not-found",
                                script = name.as_str()
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
                                        .key_exists(
                                            if !matches!(match_as, MatchAs::Lowercase) {
                                                value.clone()
                                            } else {
                                                value.to_lowercase()
                                            }
                                            .into_bytes(),
                                        )
                                        .await
                                    {
                                        input = true.into();
                                        break 'outer;
                                    }
                                }
                            } else {
                                tracing::debug!(
                                    parent: &span,
                                    context = "sieve",
                                    event = "list-not-found",
                                    list = list,
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
                                    span: &span,
                                    core: &self.core,
                                    cache: &self.inner.script_cache,
                                    message: instance.message(),
                                    modifications: &mut modifications,
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
                                tracing::warn!(
                                    parent: &span,
                                    context = "sieve",
                                    event = "send-failed",
                                    reason = format!("Lookup {list:?} not supported.")
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
                                    if let Some(dkim) = self.core.get_dkim_signer(dkim) {
                                        match dkim.sign(raw_message) {
                                            Ok(signature) => {
                                                signature.write_header(&mut headers);
                                            }
                                            Err(err) => {
                                                tracing::warn!(parent: &span,
                                                    context = "dkim",
                                                    event = "sign-failed",
                                                    reason = %err);
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
                                    .queue(headers.as_deref(), raw_message, self, &span)
                                    .await;
                            } else {
                                tracing::warn!(
                                    parent: &span,
                                    context = "sieve",
                                    event = "send-message",
                                    error = "quota-exceeded",
                                    return_path = %message.return_path_lcase,
                                    recipient = %message.recipients[0].address_lcase,
                                    reason = "Queue quota exceeded by sieve script"
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
                        tracing::warn!(
                            parent: &span,
                            context = "sieve",
                            event = "runtime-error",
                            reason = format!("Unsupported event: {unsupported:?}")
                        );
                        break;
                    }
                },
                Err(err) => {
                    tracing::warn!(parent: &span,
                        context = "sieve",
                        event = "runtime-error",
                        reason = %err
                    );
                    break;
                }
            }
        }

        // Assert global variables
        #[cfg(feature = "test_mode")]
        if let Some(expected_variables) = params.expected_variables {
            for var_name in instance.global_variable_names() {
                if instance.global_variable(var_name).unwrap().to_bool()
                    && !expected_variables.contains_key(var_name)
                {
                    panic!(
                        "Unexpected variable {var_name:?} with value {:?}\nExpected {:?}\nFound: {:?}",
                        instance.global_variable(var_name).unwrap(),
                        expected_variables.keys().collect::<Vec<_>>(),
                        instance.global_variable_names().collect::<Vec<_>>()
                    );
                }
            }

            for (name, expected) in &expected_variables {
                if let Some(value) = instance.global_variable(name.as_str()) {
                    assert_eq!(value, expected, "Variable {name:?} has unexpected value");
                } else {
                    panic!("Missing variable {name:?} with value {expected:?}\nExpected {:?}\nFound: {:?}", 
                    expected_variables.keys().collect::<Vec<_>>(),
                    instance.global_variable_names().collect::<Vec<_>>());
                }
            }
        }

        // Keep id
        // 0 = use original message
        // MAX = implicit keep
        // MAX - 1 = discard message

        if keep_id == 0 {
            ScriptResult::Accept { modifications }
        } else if let Some(mut reject_reason) = reject_reason {
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
                ScriptResult::Replace {
                    message,
                    modifications,
                }
            } else {
                ScriptResult::Accept { modifications }
            }
        } else {
            ScriptResult::Discard
        }
    }
}
