/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    ipc::{DeliveryResult, IngestMessage},
    Server,
};
use directory::Permission;
use jmap_proto::types::{state::StateChange, type_state::DataType};
use mail_parser::MessageParser;
use std::future::Future;
use store::ahash::AHashMap;

use crate::{
    email::ingest::{EmailIngest, IngestEmail, IngestSource},
    mailbox::INBOX_ID,
    sieve::{get::SieveScriptGet, ingest::SieveScriptIngest},
};

use super::state::StateManager;

pub trait MailDelivery: Sync + Send {
    fn deliver_message(
        &self,
        message: IngestMessage,
    ) -> impl Future<Output = Vec<DeliveryResult>> + Send;
}

impl MailDelivery for Server {
    async fn deliver_message(&self, message: IngestMessage) -> Vec<DeliveryResult> {
        // Read message
        let raw_message = match self
            .core
            .storage
            .blob
            .get_blob(message.message_blob.as_slice(), 0..usize::MAX)
            .await
        {
            Ok(Some(raw_message)) => raw_message,
            Ok(None) => {
                trc::event!(
                    MessageIngest(trc::MessageIngestEvent::Error),
                    Reason = "Blob not found.",
                    SpanId = message.session_id,
                    CausedBy = trc::location!()
                );

                return (0..message.recipients.len())
                    .map(|_| DeliveryResult::TemporaryFailure {
                        reason: "Blob not found.".into(),
                    })
                    .collect::<Vec<_>>();
            }
            Err(err) => {
                trc::error!(err
                    .details("Failed to fetch message blob.")
                    .span_id(message.session_id)
                    .caused_by(trc::location!()));

                return (0..message.recipients.len())
                    .map(|_| DeliveryResult::TemporaryFailure {
                        reason: "Temporary I/O error.".into(),
                    })
                    .collect::<Vec<_>>();
            }
        };

        // Obtain the UIDs for each recipient
        let mut recipients = Vec::with_capacity(message.recipients.len());
        let mut deliver_names = AHashMap::with_capacity(message.recipients.len());
        for rcpt in &message.recipients {
            match self
                .email_to_ids(&self.core.storage.directory, rcpt, message.session_id)
                .await
            {
                Ok(uids) => {
                    for uid in &uids {
                        deliver_names.insert(*uid, (DeliveryResult::Success, rcpt));
                    }
                    recipients.push(uids);
                }
                Err(err) => {
                    trc::error!(err
                        .details("Failed to lookup recipient.")
                        .ctx(trc::Key::To, rcpt.to_string())
                        .span_id(message.session_id)
                        .caused_by(trc::location!()));
                    recipients.push(vec![]);
                }
            }
        }

        // Deliver to each recipient
        for (uid, (status, rcpt)) in &mut deliver_names {
            // Obtain access token
            let result = match self.get_cached_access_token(*uid).await.and_then(|token| {
                token
                    .assert_has_permission(Permission::EmailReceive)
                    .map(|_| token)
            }) {
                Ok(access_token) => {
                    // Check if there is an active sieve script
                    match self.sieve_script_get_active(*uid).await {
                        Ok(Some(active_script)) => {
                            self.sieve_script_ingest(
                                &access_token,
                                &raw_message,
                                &message.sender_address,
                                rcpt,
                                message.session_id,
                                active_script,
                            )
                            .await
                        }
                        Ok(None) => {
                            // Ingest message
                            self.email_ingest(IngestEmail {
                                raw_message: &raw_message,
                                message: MessageParser::new().parse(&raw_message),
                                resource: access_token.as_resource_token(),
                                mailbox_ids: vec![INBOX_ID],
                                keywords: vec![],
                                received_at: None,
                                source: IngestSource::Smtp,
                                encrypt: self.core.jmap.encrypt,
                                session_id: message.session_id,
                            })
                            .await
                        }
                        Err(err) => Err(err),
                    }
                }

                Err(err) => Err(err),
            };

            match result {
                Ok(ingested_message) => {
                    // Notify state change
                    if ingested_message.change_id != u64::MAX {
                        self.broadcast_state_change(
                            StateChange::new(*uid)
                                .with_change(DataType::EmailDelivery, ingested_message.change_id)
                                .with_change(DataType::Email, ingested_message.change_id)
                                .with_change(DataType::Mailbox, ingested_message.change_id)
                                .with_change(DataType::Thread, ingested_message.change_id),
                        )
                        .await;
                    }
                }
                Err(err) => {
                    match err.as_ref() {
                        trc::EventType::Limit(trc::LimitEvent::Quota) => {
                            *status = DeliveryResult::TemporaryFailure {
                                reason: "Mailbox over quota.".into(),
                            }
                        }
                        trc::EventType::Limit(trc::LimitEvent::TenantQuota) => {
                            *status = DeliveryResult::TemporaryFailure {
                                reason: "Organization over quota.".into(),
                            }
                        }
                        trc::EventType::Security(trc::SecurityEvent::Unauthorized) => {
                            *status = DeliveryResult::PermanentFailure {
                                code: [5, 5, 0],
                                reason: "This account is not authorized to receive email.".into(),
                            }
                        }
                        trc::EventType::MessageIngest(trc::MessageIngestEvent::Error) => {
                            *status = DeliveryResult::PermanentFailure {
                                code: err
                                    .value(trc::Key::Code)
                                    .and_then(|v| v.to_uint())
                                    .map(|n| {
                                        [(n / 100) as u8, ((n % 100) / 10) as u8, (n % 10) as u8]
                                    })
                                    .unwrap_or([5, 5, 0]),
                                reason: err
                                    .value_as_str(trc::Key::Reason)
                                    .unwrap_or_default()
                                    .to_string()
                                    .into(),
                            }
                        }
                        _ => {
                            *status = DeliveryResult::TemporaryFailure {
                                reason: "Transient server failure.".into(),
                            }
                        }
                    }

                    trc::error!(err
                        .ctx(trc::Key::To, rcpt.to_string())
                        .span_id(message.session_id));
                }
            }
        }

        // Build result
        recipients
            .into_iter()
            .map(|names| {
                match names.len() {
                    1 => {
                        // Delivery to single recipient
                        deliver_names.get(&names[0]).unwrap().0.clone()
                    }
                    0 => {
                        // Something went wrong
                        DeliveryResult::TemporaryFailure {
                            reason: "Address lookup failed.".into(),
                        }
                    }
                    _ => {
                        // Delivery to list, count number of successes and failures
                        let mut success = 0;
                        let mut temp_failures = 0;
                        for uid in names {
                            match deliver_names.get(&uid).unwrap().0 {
                                DeliveryResult::Success => success += 1,
                                DeliveryResult::TemporaryFailure { .. } => temp_failures += 1,
                                DeliveryResult::PermanentFailure { .. } => {}
                            }
                        }
                        if success > temp_failures {
                            DeliveryResult::Success
                        } else if temp_failures > 0 {
                            DeliveryResult::TemporaryFailure {
                                reason: "Delivery to one or more recipients failed temporarily."
                                    .into(),
                            }
                        } else {
                            DeliveryResult::PermanentFailure {
                                code: [5, 5, 0],
                                reason: "Delivery to all recipients failed.".into(),
                            }
                        }
                    }
                }
            })
            .collect()
    }
}
