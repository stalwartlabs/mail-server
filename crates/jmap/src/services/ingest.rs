/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{DeliveryResult, IngestMessage};
use directory::QueryBy;
use jmap_proto::types::{state::StateChange, type_state::DataType};
use mail_parser::MessageParser;
use store::ahash::AHashMap;

use crate::{
    email::ingest::{IngestEmail, IngestSource},
    mailbox::INBOX_ID,
    JMAP,
};

impl JMAP {
    pub async fn deliver_message(&self, message: IngestMessage) -> Vec<DeliveryResult> {
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
                    Store(trc::StoreEvent::IngestError),
                    Reason = "Blob not found.",
                    SessionId = message.session_id,
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
                    .session_id(message.session_id));

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
                .core
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
                        .session_id(message.session_id));
                    recipients.push(vec![]);
                }
            }
        }

        // Deliver to each recipient
        for (uid, (status, rcpt)) in &mut deliver_names {
            // Check if there is an active sieve script
            let result = match self.sieve_script_get_active(*uid).await {
                Ok(Some(active_script)) => {
                    self.sieve_script_ingest(
                        &raw_message,
                        &message.sender_address,
                        rcpt,
                        *uid,
                        active_script,
                    )
                    .await
                }
                Ok(None) => {
                    let account_quota = match self
                        .core
                        .storage
                        .directory
                        .query(QueryBy::Id(*uid), false)
                        .await
                    {
                        Ok(Some(p)) => p.quota as i64,
                        Ok(None) => 0,
                        Err(_) => {
                            *status = DeliveryResult::TemporaryFailure {
                                reason: "Transient server failure.".into(),
                            };
                            continue;
                        }
                    };

                    self.email_ingest(IngestEmail {
                        raw_message: &raw_message,
                        message: MessageParser::new().parse(&raw_message),
                        account_id: *uid,
                        account_quota,
                        mailbox_ids: vec![INBOX_ID],
                        keywords: vec![],
                        received_at: None,
                        source: IngestSource::Smtp,
                        encrypt: self.core.jmap.encrypt,
                    })
                    .await
                }
                Err(err) => {
                    trc::error!(err
                        .details("Failed to ingest message.")
                        .ctx(trc::Key::To, rcpt.to_string())
                        .session_id(message.session_id));

                    *status = DeliveryResult::TemporaryFailure {
                        reason: "Transient server failure.".into(),
                    };
                    continue;
                }
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
                Err(mut err) => {
                    match err.as_ref() {
                        trc::EventType::Limit(trc::LimitEvent::Quota) => {
                            *status = DeliveryResult::TemporaryFailure {
                                reason: "Mailbox over quota.".into(),
                            }
                        }
                        trc::EventType::Store(trc::StoreEvent::IngestError) => {
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
                                    .to_string(),
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
                        .session_id(message.session_id));
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
