/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use common::listener::stream::NullIo;
use directory::QueryBy;
use jmap_proto::types::{collection::Collection, id::Id, keyword::Keyword, property::Property};
use mail_parser::MessageParser;
use sieve::{Envelope, Event, Input, Mailbox, Recipient};
use smtp::core::{Session, SessionAddress};
use store::{
    ahash::AHashSet,
    write::{now, BatchBuilder, Bincode, F_VALUE},
};
use trc::{AddContext, SieveEvent};

use crate::{
    email::ingest::{IngestEmail, IngestSource, IngestedEmail},
    mailbox::{INBOX_ID, TRASH_ID},
    sieve::SeenIdHash,
    JMAP,
};

use super::ActiveScript;

struct SieveMessage<'x> {
    pub raw_message: Cow<'x, [u8]>,
    pub file_into: Vec<u32>,
    pub flags: Vec<Keyword>,
}

impl JMAP {
    #[allow(clippy::blocks_in_conditions)]
    pub async fn sieve_script_ingest(
        &self,
        raw_message: &[u8],
        envelope_from: &str,
        envelope_to: &str,
        account_id: u32,
        session_id: u64,
        mut active_script: ActiveScript,
    ) -> trc::Result<IngestedEmail> {
        // Parse message
        let message = if let Some(message) = MessageParser::new().parse(raw_message) {
            message
        } else {
            return Err(
                trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                    .ctx(trc::Key::Code, 550)
                    .ctx(trc::Key::Reason, "Failed to parse e-mail message."),
            );
        };

        // Obtain mailboxIds
        let mailbox_ids = self
            .mailbox_get_or_create(account_id)
            .await
            .caused_by(trc::location!())?;

        // Create Sieve instance
        let mut instance = self.core.sieve.untrusted_runtime.filter_parsed(message);

        // Set account name and obtain quota
        let (account_quota, mail_from) = match self
            .core
            .storage
            .directory
            .query(QueryBy::Id(account_id), false)
            .await
        {
            Ok(Some(p)) => {
                instance.set_user_full_name(p.description().unwrap_or_else(|| p.name()));
                (p.quota as i64, p.emails.into_iter().next())
            }
            Ok(None) => (0, None),
            Err(err) => {
                return Err(err.caused_by(trc::location!()));
            }
        };

        // Set account address
        let mail_from = mail_from.unwrap_or_else(|| envelope_to.to_string());
        instance.set_user_address(&mail_from);

        // Set envelope
        instance.set_envelope(Envelope::From, envelope_from);
        instance.set_envelope(Envelope::To, envelope_to);

        let mut input = Input::script(active_script.script_name, active_script.script.clone());

        let mut do_discard = false;
        let mut do_deliver = false;

        let mut new_ids = AHashSet::new();
        let mut reject_reason = None;
        let mut messages: Vec<SieveMessage> = vec![SieveMessage {
            raw_message: raw_message.into(),
            file_into: Vec::new(),
            flags: Vec::new(),
        }];
        let now = now();
        let mut ingested_message = IngestedEmail {
            id: Id::default(),
            change_id: u64::MAX,
            blob_id: Default::default(),
            size: raw_message.len(),
            imap_uids: Vec::new(),
        };

        while let Some(event) = instance.run(input) {
            match event {
                Ok(event) => match event {
                    Event::IncludeScript { name, .. } => {
                        if let Ok(Some(script)) =
                            self.sieve_script_get_by_name(account_id, &name).await
                        {
                            input = Input::script(name, script);
                        } else {
                            input = false.into();
                        }
                    }
                    Event::MailboxExists {
                        mailboxes,
                        special_use,
                    } => {
                        if !mailboxes.is_empty() {
                            let mut special_use_ids = Vec::with_capacity(special_use.len());
                            for role in special_use {
                                special_use_ids.push(if role.eq_ignore_ascii_case("inbox") {
                                    INBOX_ID
                                } else if role.eq_ignore_ascii_case("trash") {
                                    TRASH_ID
                                } else {
                                    let mut mailbox_id = u32::MAX;
                                    let role = role.to_ascii_lowercase();
                                    if is_valid_role(&role) {
                                        if let Ok(Some(mailbox_id_)) =
                                            self.mailbox_get_by_role(account_id, &role).await
                                        {
                                            mailbox_id = mailbox_id_;
                                        }
                                    }
                                    mailbox_id
                                });
                            }

                            let mut result = true;
                            for mailbox in mailboxes {
                                match mailbox {
                                    Mailbox::Name(name) => {
                                        if !matches!(
                                            self.mailbox_get_by_name(account_id, &name).await,
                                            Ok(Some(document_id)) if special_use_ids.is_empty() ||
                                            special_use_ids.contains(&document_id)
                                        ) {
                                            result = false;
                                            break;
                                        }
                                    }
                                    Mailbox::Id(id) => {
                                        if !matches!(Id::from_bytes(id.as_bytes()), Some(id) if
                                                            mailbox_ids.contains(id.document_id()) &&
                                                            (special_use_ids.is_empty() ||
                                                            special_use_ids.contains(&id.document_id())))
                                        {
                                            result = false;
                                            break;
                                        }
                                    }
                                }
                            }
                            input = result.into();
                        } else if !special_use.is_empty() {
                            let mut result = true;

                            for role in special_use {
                                if !role.eq_ignore_ascii_case("inbox")
                                    && !role.eq_ignore_ascii_case("trash")
                                {
                                    let role = role.to_ascii_lowercase();
                                    if !is_valid_role(&role)
                                        || !matches!(
                                            self.mailbox_get_by_role(account_id, &role).await,
                                            Ok(Some(_))
                                        )
                                    {
                                        result = false;
                                        break;
                                    }
                                }
                            }
                            input = result.into();
                        } else {
                            input = false.into();
                        }
                    }
                    Event::DuplicateId { id, expiry, last } => {
                        let id_hash = SeenIdHash::new(&id, expiry + now);
                        let seen_id = active_script.seen_ids.ids.contains(&id_hash);
                        if !seen_id || last {
                            new_ids.insert(id_hash);
                        }

                        input = seen_id.into();
                    }
                    Event::Discard => {
                        do_discard = true;
                        input = true.into();
                    }
                    Event::Reject { reason, .. } => {
                        reject_reason = reason.into();
                        do_discard = true;
                        input = true.into();
                    }
                    Event::Keep { flags, message_id } => {
                        if let Some(message) = messages.get_mut(message_id) {
                            message.flags = flags.into_iter().map(Keyword::from).collect();
                            if !message.file_into.contains(&INBOX_ID) {
                                message.file_into.push(INBOX_ID);
                            }
                            do_deliver = true;
                        } else {
                            trc::event!(
                                Sieve(SieveEvent::UnexpectedError),
                                Details = "Unknown message id.",
                                MessageId = message_id,
                                SpanId = session_id
                            );
                        }
                        input = true.into();
                    }
                    Event::FileInto {
                        folder,
                        flags,
                        mailbox_id,
                        special_use,
                        create,
                        message_id,
                    } => {
                        let mut target_id = u32::MAX;

                        // Find mailbox by Id
                        if let Some(mailbox_id) =
                            mailbox_id.and_then(|m| Id::from_bytes(m.as_bytes()))
                        {
                            let mailbox_id = mailbox_id.document_id();
                            if mailbox_ids.contains(mailbox_id) {
                                target_id = mailbox_id;
                            }
                        }

                        // Find mailbox by role
                        if let Some(special_use) = special_use {
                            if target_id == u32::MAX {
                                if special_use.eq_ignore_ascii_case("inbox") {
                                    target_id = INBOX_ID;
                                } else if special_use.eq_ignore_ascii_case("trash") {
                                    target_id = TRASH_ID;
                                } else {
                                    let role = special_use.to_ascii_lowercase();
                                    if is_valid_role(&role) {
                                        if let Ok(Some(mailbox_id_)) =
                                            self.mailbox_get_by_role(account_id, &role).await
                                        {
                                            target_id = mailbox_id_;
                                        }
                                    }
                                }
                            }
                        }

                        // Find mailbox by name
                        if target_id == u32::MAX {
                            if !create {
                                if let Ok(Some(document_id)) =
                                    self.mailbox_get_by_name(account_id, &folder).await
                                {
                                    target_id = document_id;
                                }
                            } else if let Ok(Some((document_id, changes))) =
                                self.mailbox_create_path(account_id, &folder).await
                            {
                                target_id = document_id;
                                if let Some(change_id) = changes {
                                    ingested_message.change_id = change_id;
                                }
                            }
                        }

                        // Default to Inbox
                        if target_id == u32::MAX {
                            target_id = INBOX_ID;
                        }

                        if let Some(message) = messages.get_mut(message_id) {
                            message.flags = flags.into_iter().map(Keyword::from).collect();
                            if !message.file_into.contains(&target_id) {
                                message.file_into.push(target_id);
                            }
                            do_deliver = true;
                        } else {
                            trc::event!(
                                Sieve(SieveEvent::UnexpectedError),
                                Details = "Unknown message id.",
                                MessageId = message_id,
                                SpanId = session_id
                            );
                        }
                        input = true.into();
                    }
                    Event::SendMessage {
                        recipient,
                        message_id,
                        ..
                    } => {
                        input = true.into();
                        if let Some(message) = messages.get(message_id) {
                            let recipients = match recipient {
                                Recipient::Address(rcpt) => vec![SessionAddress::new(rcpt)],
                                Recipient::Group(rcpts) => {
                                    rcpts.into_iter().map(SessionAddress::new).collect()
                                }
                                Recipient::List(_) => {
                                    // Not yet implemented
                                    continue;
                                }
                            };

                            if message.raw_message.len() <= self.core.jmap.mail_max_size {
                                trc::event!(
                                    Sieve(SieveEvent::SendMessage),
                                    From = mail_from.clone(),
                                    To = recipients
                                        .iter()
                                        .map(|r| trc::Value::String(r.address_lcase.clone()))
                                        .collect::<Vec<_>>(),
                                    Size = message.raw_message.len(),
                                    SpanId = session_id
                                );

                                Session::<NullIo>::sieve(
                                    self.smtp.clone(),
                                    SessionAddress::new(mail_from.clone()),
                                    recipients,
                                    message.raw_message.to_vec(),
                                    0,
                                )
                                .queue_message()
                                .await;
                            } else {
                                trc::event!(
                                    Sieve(SieveEvent::MessageTooLarge),
                                    From = mail_from.clone(),
                                    To = recipients
                                        .iter()
                                        .map(|r| trc::Value::String(r.address_lcase.clone()))
                                        .collect::<Vec<_>>(),
                                    Size = message.raw_message.len(),
                                    Limit = self.core.jmap.mail_max_size,
                                    SpanId = session_id,
                                );
                            }
                        } else {
                            trc::event!(
                                Sieve(SieveEvent::UnexpectedError),
                                Details = "Unknown message id.",
                                MessageId = message_id,
                                SpanId = session_id
                            );

                            continue;
                        }
                    }
                    Event::ListContains { .. }
                    | Event::Function { .. }
                    | Event::Notify { .. }
                    | Event::SetEnvelope { .. } => {
                        // Not allowed
                        input = false.into();
                    }
                    Event::CreatedMessage { message, .. } => {
                        messages.push(SieveMessage {
                            raw_message: message.into(),
                            file_into: Vec::new(),
                            flags: Vec::new(),
                        });
                        input = true.into();
                    }
                },

                #[cfg(feature = "test_mode")]
                Err(sieve::runtime::RuntimeError::ScriptErrorMessage(err)) => {
                    panic!("Sieve test failed: {}", err);
                }

                Err(err) => {
                    trc::event!(
                        Sieve(SieveEvent::RuntimeError),
                        Reason = err.to_string(),
                        SpanId = session_id
                    );

                    input = true.into();
                }
            }
        }

        // Fail-safe, no discard and no keep seen, assume that something went wrong and file anyway.
        if !do_deliver && !do_discard {
            messages[0].file_into.push(INBOX_ID);
        }

        // Deliver messages
        let mut last_temp_error = None;
        let mut has_delivered = false;
        for (message_id, sieve_message) in messages.into_iter().enumerate() {
            if !sieve_message.file_into.is_empty() {
                // Parse message if needed
                let message = if message_id == 0 && !instance.has_message_changed() {
                    instance.take_message()
                } else if let Some(message) =
                    MessageParser::new().parse(sieve_message.raw_message.as_ref())
                {
                    message
                } else {
                    trc::event!(
                        Sieve(SieveEvent::UnexpectedError),
                        Details = "Failed to parse Sieve generated message.",
                        SpanId = session_id
                    );

                    continue;
                };

                // Deliver message
                match self
                    .email_ingest(IngestEmail {
                        raw_message: &sieve_message.raw_message,
                        message: message.into(),
                        account_id,
                        account_quota,
                        mailbox_ids: sieve_message.file_into,
                        keywords: sieve_message.flags,
                        received_at: None,
                        source: IngestSource::Smtp,
                        encrypt: self.core.jmap.encrypt,
                        session_id,
                    })
                    .await
                {
                    Ok(ingested_message_) => {
                        has_delivered = true;
                        ingested_message = ingested_message_;
                    }
                    Err(err) => {
                        last_temp_error = err.into();
                    }
                }
            }
        }

        // Save new ids script changes
        if !new_ids.is_empty() || active_script.seen_ids.has_changes {
            active_script.seen_ids.ids.extend(new_ids);
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::SieveScript)
                .update_document(active_script.document_id)
                .value(
                    Property::EmailIds,
                    Bincode::new(active_script.seen_ids),
                    F_VALUE,
                );
            let _ = self.write_batch(batch).await;
        }

        if let Some(reject_reason) = reject_reason {
            Err(
                trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                    .ctx(trc::Key::Code, 571)
                    .ctx(trc::Key::Reason, reject_reason),
            )
        } else if has_delivered || last_temp_error.is_none() {
            Ok(ingested_message)
        } else {
            // There were problems during delivery
            #[allow(clippy::unnecessary_unwrap)]
            Err(last_temp_error.unwrap())
        }
    }
}

#[inline(always)]
pub fn is_valid_role(role: &str) -> bool {
    [
        "inbox",
        "trash",
        "spam",
        "junk",
        "drafts",
        "archive",
        "sent",
        "important",
    ]
    .contains(&role)
}
