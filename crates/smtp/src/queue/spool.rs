/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::queue::DomainPart;
use std::borrow::Cow;
use std::time::{Duration, SystemTime};
use store::write::key::DeserializeBigEndian;
use store::write::{now, BatchBuilder, Bincode, BlobOp, QueueClass, QueueEvent, ValueClass};
use store::{Deserialize, IterateParams, Serialize, ValueKey, U64_LEN};
use utils::BlobHash;

use crate::core::SMTP;

use super::{
    Domain, Event, Message, QueueEnvelope, QueueId, QuotaKey, Recipient, Schedule, Status,
};

pub const LOCK_EXPIRY: u64 = 300;

#[derive(Debug)]
pub struct QueueEventLock {
    pub due: u64,
    pub queue_id: u64,
    pub lock_expiry: u64,
}

impl SMTP {
    pub fn new_message(
        &self,
        return_path: impl Into<String>,
        return_path_lcase: impl Into<String>,
        return_path_domain: impl Into<String>,
    ) -> Message {
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Message {
            id: self.inner.snowflake_id.generate().unwrap_or(created),
            created,
            return_path: return_path.into(),
            return_path_lcase: return_path_lcase.into(),
            return_path_domain: return_path_domain.into(),
            recipients: Vec::with_capacity(1),
            domains: Vec::with_capacity(1),
            flags: 0,
            env_id: None,
            priority: 0,
            size: 0,
            blob_hash: Default::default(),
            quota_keys: Vec::new(),
        }
    }

    pub async fn next_event(&self) -> Vec<QueueEventLock> {
        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
            due: 0,
            queue_id: 0,
        })));
        let to_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
            due: u64::MAX,
            queue_id: u64::MAX,
        })));

        let mut events = Vec::new();
        let now = now();
        let result = self
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    let event = QueueEventLock {
                        due: key.deserialize_be_u64(0)?,
                        queue_id: key.deserialize_be_u64(U64_LEN)?,
                        lock_expiry: u64::deserialize(value)?,
                    };
                    let do_continue = event.due <= now;
                    if event.lock_expiry < now {
                        events.push(event);
                    } else {
                        tracing::trace!(
                            context = "queue",
                            event = "locked",
                            id = event.queue_id,
                            due = event.due,
                            expiry = event.lock_expiry - now,
                            "Queue event locked by another process."
                        );
                    }
                    Ok(do_continue)
                },
            )
            .await;

        if let Err(err) = result {
            tracing::error!(
                context = "queue",
                event = "error",
                "Failed to read from store: {}",
                err
            );
        }

        events
    }

    pub async fn try_lock_event(&self, mut event: QueueEventLock) -> Option<QueueEventLock> {
        let mut batch = BatchBuilder::new();
        batch.assert_value(
            ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                due: event.due,
                queue_id: event.queue_id,
            })),
            event.lock_expiry,
        );
        event.lock_expiry = now() + LOCK_EXPIRY;
        batch.set(
            ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                due: event.due,
                queue_id: event.queue_id,
            })),
            event.lock_expiry.serialize(),
        );
        match self.core.storage.data.write(batch.build()).await {
            Ok(_) => Some(event),
            Err(err) if err.is_assertion_failure() => {
                tracing::debug!(
                    context = "queue",
                    event = "locked",
                    id = event.queue_id,
                    due = event.due,
                    "Lock busy: Event already locked."
                );
                None
            }
            Err(err) => {
                tracing::error!(context = "queue", event = "error", "Lock error: {}", err);
                None
            }
        }
    }

    pub async fn read_message(&self, id: QueueId) -> Option<Message> {
        match self
            .core
            .storage
            .data
            .get_value::<Bincode<Message>>(ValueKey::from(ValueClass::Queue(QueueClass::Message(
                id,
            ))))
            .await
        {
            Ok(Some(message)) => Some(message.inner),
            Ok(None) => None,
            Err(err) => {
                tracing::error!(
                    context = "queue",
                    event = "error",
                    "Failed to read message from store: {}",
                    err
                );
                None
            }
        }
    }
}

impl Message {
    pub async fn queue(
        mut self,
        raw_headers: Option<&[u8]>,
        raw_message: &[u8],
        core: &SMTP,
    ) -> bool {
        // Write blob
        let message = if let Some(raw_headers) = raw_headers {
            let mut message = Vec::with_capacity(raw_headers.len() + raw_message.len());
            message.extend_from_slice(raw_headers);
            message.extend_from_slice(raw_message);
            Cow::Owned(message)
        } else {
            raw_message.into()
        };
        self.blob_hash = BlobHash::from(message.as_ref());

        // Generate id
        if self.size == 0 {
            self.size = message.len();
        }

        // Reserve and write blob
        let mut batch = BatchBuilder::new();
        let reserve_until = now() + 120;
        batch.set(
            BlobOp::Reserve {
                hash: self.blob_hash.clone(),
                until: reserve_until,
            },
            0u32.serialize(),
        );
        if let Err(err) = core.core.storage.data.write(batch.build()).await {
            tracing::error!(
                context = "queue",
                event = "error",
                "Failed to write to data store: {}",
                err
            );
            return false;
        }
        if let Err(err) = core
            .core
            .storage
            .blob
            .put_blob(self.blob_hash.as_slice(), message.as_ref())
            .await
        {
            tracing::error!(
                context = "queue",
                event = "error",
                "Failed to write to blob store: {}",
                err
            );
            return false;
        }

        tracing::info!(
            context = "queue",
            event = "scheduled",
            id = self.id,
            from = if !self.return_path.is_empty() {
                self.return_path.as_str()
            } else {
                "<>"
            },
            nrcpts = self.recipients.len(),
            size = self.size,
            "Message queued for delivery."
        );

        // Write message to queue
        let mut batch = BatchBuilder::new();

        // Reserve quotas
        for quota_key in &self.quota_keys {
            match quota_key {
                QuotaKey::Count { key, .. } => {
                    batch.add(ValueClass::Queue(QueueClass::QuotaCount(key.clone())), 1);
                }
                QuotaKey::Size { key, .. } => {
                    batch.add(
                        ValueClass::Queue(QueueClass::QuotaSize(key.clone())),
                        self.size as i64,
                    );
                }
            }
        }
        batch
            .set(
                ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                    due: self.next_event().unwrap_or_default(),
                    queue_id: self.id,
                })),
                0u64.serialize(),
            )
            .clear(BlobOp::Reserve {
                hash: self.blob_hash.clone(),
                until: reserve_until,
            })
            .set(
                BlobOp::LinkId {
                    hash: self.blob_hash.clone(),
                    id: self.id,
                },
                vec![],
            )
            .set(
                BlobOp::Commit {
                    hash: self.blob_hash.clone(),
                },
                vec![],
            )
            .set(
                ValueClass::Queue(QueueClass::Message(self.id)),
                Bincode::new(self).serialize(),
            );

        if let Err(err) = core.core.storage.data.write(batch.build()).await {
            tracing::error!(
                context = "queue",
                event = "error",
                "Failed to write to store: {}",
                err
            );
            return false;
        }

        // Queue the message
        if core.inner.queue_tx.send(Event::Reload).await.is_err() {
            tracing::warn!(
                context = "queue",
                event = "error",
                "Queue channel closed: Message queued but won't be sent until next restart."
            );
        }

        true
    }

    pub async fn add_recipient_parts(
        &mut self,
        rcpt: impl Into<String>,
        rcpt_lcase: impl Into<String>,
        rcpt_domain: impl Into<String>,
        core: &SMTP,
    ) {
        let rcpt_domain = rcpt_domain.into();
        let domain_idx =
            if let Some(idx) = self.domains.iter().position(|d| d.domain == rcpt_domain) {
                idx
            } else {
                let idx = self.domains.len();

                self.domains.push(Domain {
                    domain: rcpt_domain,
                    retry: Schedule::now(),
                    notify: Schedule::now(),
                    expires: 0,
                    status: Status::Scheduled,
                });

                let expires = core
                    .core
                    .eval_if(
                        &core.core.smtp.queue.expire,
                        &QueueEnvelope::new(self, idx),
                        self.id,
                    )
                    .await
                    .unwrap_or_else(|| Duration::from_secs(5 * 86400));

                // Update expiration
                let domain = self.domains.last_mut().unwrap();
                domain.notify = Schedule::later(expires + Duration::from_secs(10));
                domain.expires = now() + expires.as_secs();

                idx
            };
        self.recipients.push(Recipient {
            domain_idx,
            address: rcpt.into(),
            address_lcase: rcpt_lcase.into(),
            status: Status::Scheduled,
            flags: 0,
            orcpt: None,
        });
    }

    pub async fn add_recipient(&mut self, rcpt: impl Into<String>, core: &SMTP) {
        let rcpt = rcpt.into();
        let rcpt_lcase = rcpt.to_lowercase();
        let rcpt_domain = rcpt_lcase.domain_part().to_string();
        self.add_recipient_parts(rcpt, rcpt_lcase, rcpt_domain, core)
            .await;
    }

    pub async fn save_changes(
        mut self,
        core: &SMTP,
        prev_event: Option<u64>,
        next_event: Option<u64>,
    ) -> bool {
        debug_assert!(prev_event.is_some() == next_event.is_some());

        let mut batch = BatchBuilder::new();

        // Release quota for completed deliveries
        self.release_quota(&mut batch);

        // Update message queue
        let mut batch = BatchBuilder::new();
        if let (Some(prev_event), Some(next_event)) = (prev_event, next_event) {
            batch
                .clear(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                    due: prev_event,
                    queue_id: self.id,
                })))
                .set(
                    ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                        due: next_event,
                        queue_id: self.id,
                    })),
                    0u64.serialize(),
                );
        }

        batch.set(
            ValueClass::Queue(QueueClass::Message(self.id)),
            Bincode::new(self).serialize(),
        );

        if let Err(err) = core.core.storage.data.write(batch.build()).await {
            tracing::error!(
                context = "queue",
                event = "error",
                "Failed to update queued message: {}",
                err
            );
            false
        } else {
            true
        }
    }

    pub async fn remove(self, core: &SMTP, prev_event: u64) -> bool {
        let mut batch = BatchBuilder::new();

        // Release all quotas
        for quota_key in self.quota_keys {
            match quota_key {
                QuotaKey::Count { key, .. } => {
                    batch.add(ValueClass::Queue(QueueClass::QuotaCount(key)), -1);
                }
                QuotaKey::Size { key, .. } => {
                    batch.add(
                        ValueClass::Queue(QueueClass::QuotaSize(key)),
                        -(self.size as i64),
                    );
                }
            }
        }

        batch
            .clear(BlobOp::LinkId {
                hash: self.blob_hash.clone(),
                id: self.id,
            })
            .clear(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                due: prev_event,
                queue_id: self.id,
            })))
            .clear(ValueClass::Queue(QueueClass::Message(self.id)));

        if let Err(err) = core.core.storage.data.write(batch.build()).await {
            tracing::error!(
                context = "queue",
                event = "error",
                "Failed to update queued message: {}",
                err
            );
            false
        } else {
            true
        }
    }
}
