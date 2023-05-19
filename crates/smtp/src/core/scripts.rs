/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::{borrow::Cow, process::Command, sync::Arc, time::Duration};

use ahash::AHashMap;
use mail_auth::common::headers::HeaderWriter;
use sieve::{
    compiler::grammar::actions::action_redirect::{ByMode, ByTime, Notify, NotifyItem, Ret},
    CommandType, Envelope, Event, Input, MatchAs, Recipient, Sieve,
};
use smtp_proto::{
    MAIL_BY_NOTIFY, MAIL_BY_RETURN, MAIL_BY_TRACE, MAIL_RET_FULL, MAIL_RET_HDRS, RCPT_NOTIFY_DELAY,
    RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    runtime::Handle,
};

use crate::{
    lookup::Lookup,
    queue::{DomainPart, InstantFromTimestamp, Message},
};

use super::{Session, SMTP};

pub enum ScriptResult {
    Accept,
    Replace(Vec<u8>),
    Reject(String),
    Discard,
}

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn run_script(
        &self,
        script: Arc<Sieve>,
        message: Option<Arc<Vec<u8>>>,
    ) -> ScriptResult {
        let core = self.core.clone();
        let span = self.span.clone();

        // Set environment variables
        let mut vars_env: AHashMap<String, Cow<str>> = AHashMap::with_capacity(6);
        vars_env.insert(
            "remote_ip".to_string(),
            self.data.remote_ip.to_string().into(),
        );
        vars_env.insert(
            "helo_domain".to_string(),
            self.data.helo_domain.clone().into(),
        );
        vars_env.insert(
            "authenticated_as".to_string(),
            self.data.authenticated_as.clone().into(),
        );

        // Set envelope
        let envelope = if let Some(mail_from) = &self.data.mail_from {
            let mut envelope: Vec<(Envelope, Cow<str>)> = Vec::with_capacity(6);
            envelope.push((Envelope::From, mail_from.address.clone().into()));
            if let Some(env_id) = &mail_from.dsn_info {
                envelope.push((Envelope::Envid, env_id.clone().into()));
            }
            if let Some(rcpt) = self.data.rcpt_to.last() {
                envelope.push((Envelope::To, rcpt.address.clone().into()));
                if let Some(orcpt) = &rcpt.dsn_info {
                    envelope.push((Envelope::Orcpt, orcpt.clone().into()));
                }
            }
            if (mail_from.flags & MAIL_RET_FULL) != 0 {
                envelope.push((Envelope::Ret, "FULL".into()));
            } else if (mail_from.flags & MAIL_RET_HDRS) != 0 {
                envelope.push((Envelope::Ret, "HDRS".into()));
            }
            if (mail_from.flags & MAIL_BY_NOTIFY) != 0 {
                envelope.push((Envelope::ByMode, "N".into()));
            } else if (mail_from.flags & MAIL_BY_RETURN) != 0 {
                envelope.push((Envelope::ByMode, "R".into()));
            }
            envelope
        } else {
            Vec::with_capacity(0)
        };

        let handle = Handle::current();
        self.core
            .spawn_worker(move || {
                core.run_script_blocking(script, vars_env, envelope, message, handle, span)
            })
            .await
            .unwrap_or(ScriptResult::Accept)
    }
}

impl SMTP {
    fn run_script_blocking(
        &self,
        script: Arc<Sieve>,
        vars_env: AHashMap<String, Cow<'static, str>>,
        envelope: Vec<(Envelope, Cow<'static, str>)>,
        message: Option<Arc<Vec<u8>>>,
        handle: Handle,
        span: tracing::Span,
    ) -> ScriptResult {
        // Create filter instance
        let mut instance = self
            .sieve
            .runtime
            .filter(message.as_deref().map_or(b"", |m| &m[..]))
            .with_vars_env(vars_env)
            .with_envelope_list(envelope)
            .with_user_address(&self.sieve.config.from_addr)
            .with_user_full_name(&self.sieve.config.from_name);
        let mut input = Input::script("__script", script);
        let mut messages: Vec<Vec<u8>> = Vec::new();

        let mut reject_reason = None;
        let mut keep_id = usize::MAX;

        // Start event loop
        while let Some(result) = instance.run(input) {
            match result {
                Ok(event) => match event {
                    Event::IncludeScript { name, optional } => {
                        if let Some(script) = self.sieve.scripts.get(name.as_str()) {
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
                            if let Some(list) = self.sieve.lookup.get(&list) {
                                for value in &values {
                                    let result = if !matches!(match_as, MatchAs::Lowercase) {
                                        handle.block_on(list.contains(value))
                                    } else {
                                        handle.block_on(list.contains(&value.to_lowercase()))
                                    };
                                    if let Some(true) = result {
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
                    Event::Execute {
                        command_type,
                        command,
                        arguments,
                    } => match command_type {
                        CommandType::Query => {
                            if let Some(db) = &self.sieve.config.db {
                                if command
                                    .as_bytes()
                                    .get(..6)
                                    .map_or(false, |q| q.eq_ignore_ascii_case(b"SELECT"))
                                {
                                    input = handle
                                        .block_on(db.exists(&command, arguments.into_iter()))
                                        .unwrap_or(false)
                                        .into();
                                } else {
                                    input = handle
                                        .block_on(db.execute(&command, arguments.into_iter()))
                                        .into();
                                }
                            } else {
                                tracing::warn!(
                                    parent: &span,
                                    context = "sieve",
                                    event = "config-error",
                                    reason = "No database configured",
                                );
                                input = false.into();
                            }
                        }
                        CommandType::Binary => {
                            match Command::new(command).args(arguments).output() {
                                Ok(result) => {
                                    input = result.status.success().into();
                                }
                                Err(err) => {
                                    tracing::warn!(
                                        parent: &span,
                                        context = "sieve",
                                        event = "execute-failed",
                                        reason = %err,
                                    );
                                    input = false.into();
                                }
                            }
                        }
                    },
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
                        let return_path_lcase = self.sieve.config.return_path.to_lowercase();
                        let return_path_domain = return_path_lcase.domain_part().to_string();
                        let mut message = Message::new_boxed(
                            self.sieve.config.return_path.clone(),
                            return_path_lcase,
                            return_path_domain,
                        );
                        match recipient {
                            Recipient::Address(rcpt) => {
                                handle.block_on(message.add_recipient(rcpt, &self.queue.config));
                            }
                            Recipient::Group(rcpt_list) => {
                                for rcpt in rcpt_list {
                                    handle
                                        .block_on(message.add_recipient(rcpt, &self.queue.config));
                                }
                            }
                            Recipient::List(list) => {
                                if let Some(list) = self.sieve.lookup.get(&list) {
                                    match list.as_ref() {
                                        Lookup::List(items) => {
                                            for rcpt in items {
                                                handle.block_on(
                                                    message.add_recipient(rcpt, &self.queue.config),
                                                );
                                            }
                                        }
                                        Lookup::Sql(sql) => {
                                            if let Some(items) = handle.block_on(sql.fetch_many(""))
                                            {
                                                for rcpt in items {
                                                    handle.block_on(
                                                        message.add_recipient(
                                                            rcpt,
                                                            &self.queue.config,
                                                        ),
                                                    );
                                                }
                                            }
                                        }
                                        _ => (),
                                    }
                                } else {
                                    tracing::warn!(
                                        parent: &span,
                                        context = "sieve",
                                        event = "send-failed",
                                        reason = format!("Lookup {list:?} not found.")
                                    );
                                }
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
                                let rlimit = Duration::from_secs(rlimit);
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
                                let alimit = (alimit as u64).to_instant();
                                match mode {
                                    ByMode::Notify => {
                                        for domain in &mut message.domains {
                                            domain.notify.due = alimit;
                                        }
                                    }
                                    ByMode::Return => {
                                        for domain in &mut message.domains {
                                            domain.expires = alimit;
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
                        if let Some(raw_message) = messages.get(message_id - 1) {
                            let headers = if !self.sieve.config.sign.is_empty() {
                                let mut headers = Vec::new();
                                for dkim in &self.sieve.config.sign {
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
                                Some(headers)
                            } else {
                                None
                            };

                            handle.block_on(self.queue.queue_message(
                                message,
                                headers.as_deref(),
                                raw_message,
                                &span,
                            ));
                        }

                        input = true.into();
                    }
                    Event::CreatedMessage { message, .. } => {
                        messages.push(message);
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

        // Keep id
        // 0 = use original message
        // MAX = implicit keep
        // MAX - 1 = discard message

        if keep_id == 0 {
            ScriptResult::Accept
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
            messages
                .into_iter()
                .nth(keep_id - 1)
                .map(ScriptResult::Replace)
                .unwrap_or(ScriptResult::Accept)
        } else {
            ScriptResult::Discard
        }
    }
}
