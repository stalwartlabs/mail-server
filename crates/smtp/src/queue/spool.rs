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

use crate::queue::DomainPart;
use std::borrow::Cow;
use std::time::{Duration, SystemTime};
use store::write::key::DeserializeBigEndian;
use store::write::{now, BatchBuilder, Bincode, BlobOp, QueueClass, QueueEvent, ValueClass};
use store::{IterateParams, Serialize, ValueKey, U64_LEN};
use utils::BlobHash;

use crate::core::{QueueCore, SMTP};

use super::{
    Domain, Event, Message, QueueId, QuotaKey, Recipient, Schedule, SimpleEnvelope, Status,
};

impl QueueCore {
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
            id: self.snowflake_id.generate().unwrap_or(created),
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
}

impl SMTP {
    pub async fn next_event(&self) -> Vec<QueueEvent> {
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
            .shared
            .default_data_store
            .iterate(
                IterateParams::new(from_key, to_key).ascending().no_values(),
                |key, _| {
                    let event = QueueEvent {
                        due: key.deserialize_be_u64(1)?,
                        queue_id: key.deserialize_be_u64(U64_LEN + 1)?,
                    };
                    let do_continue = event.due <= now;
                    events.push(event);
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

    pub async fn read_message(&self, id: QueueId) -> Option<Message> {
        match self
            .shared
            .default_data_store
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
        span: &tracing::Span,
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
        batch.with_account_id(u32::MAX).set(
            BlobOp::Reserve {
                hash: self.blob_hash.clone(),
                until: self.next_delivery_event() + 3600,
            },
            0u32.serialize(),
        );
        if let Err(err) = core.shared.default_data_store.write(batch.build()).await {
            tracing::error!(
                parent: span,
                context = "queue",
                event = "error",
                "Failed to write to data store: {}",
                err
            );
            return false;
        }
        if let Err(err) = core
            .shared
            .default_blob_store
            .put_blob(self.blob_hash.as_slice(), message.as_ref())
            .await
        {
            tracing::error!(
                parent: span,
                context = "queue",
                event = "error",
                "Failed to write to blob store: {}",
                err
            );
            return false;
        }

        tracing::info!(
            parent: span,
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
        batch
            .set(
                ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                    due: self.next_event().unwrap_or_default(),
                    queue_id: self.id,
                })),
                vec![],
            )
            .set(
                ValueClass::Queue(QueueClass::Message(self.id)),
                Bincode::new(self).serialize(),
            );

        if let Err(err) = core.shared.default_data_store.write(batch.build()).await {
            tracing::error!(
                parent: span,
                context = "queue",
                event = "error",
                "Failed to write to store: {}",
                err
            );
            return false;
        }

        // Queue the message
        if core.queue.tx.send(Event::Reload).await.is_err() {
            tracing::warn!(
                parent: span,
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
                let expires = core
                    .eval_if(
                        &core.queue.config.expire,
                        &SimpleEnvelope::new(self, &rcpt_domain),
                    )
                    .await
                    .unwrap_or_else(|| Duration::from_secs(5 * 86400));
                self.domains.push(Domain {
                    domain: rcpt_domain,
                    retry: Schedule::now(),
                    notify: Schedule::later(expires + Duration::from_secs(10)),
                    expires: now() + expires.as_secs(),
                    status: Status::Scheduled,
                    disable_tls: false,
                });
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
        if let Some(prev_event) = prev_event {
            batch.clear(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                due: prev_event,
                queue_id: self.id,
            })));
        }
        if let Some(next_event) = next_event {
            batch.set(
                ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                    due: next_event,
                    queue_id: self.id,
                })),
                vec![],
            );
        }
        batch
            .with_account_id(u32::MAX)
            .set(
                BlobOp::Reserve {
                    hash: self.blob_hash.clone(),
                    until: self.next_delivery_event() + 3600,
                },
                0u32.serialize(),
            )
            .set(
                ValueClass::Queue(QueueClass::Message(self.id)),
                Bincode::new(self).serialize(),
            );

        if let Err(err) = core.shared.default_data_store.write(batch.build()).await {
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
                    batch.clear(ValueClass::Queue(QueueClass::QuotaCount(key)));
                }
                QuotaKey::Size { key, .. } => {
                    batch.clear(ValueClass::Queue(QueueClass::QuotaSize(key)));
                }
            }
        }

        batch
            .clear(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                due: prev_event,
                queue_id: self.id,
            })))
            .clear(ValueClass::Queue(QueueClass::Message(self.id)));

        if let Err(err) = core.shared.default_data_store.write(batch.build()).await {
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
