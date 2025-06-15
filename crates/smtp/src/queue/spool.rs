/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::queue::DomainPart;
use common::ipc::QueueEvent;
use common::{KV_LOCK_QUEUE_MESSAGE, Server};

use std::borrow::Cow;
use std::future::Future;
use std::time::{Duration, SystemTime};
use store::write::key::DeserializeBigEndian;
use store::write::{
    AlignedBytes, Archive, Archiver, BatchBuilder, BlobOp, QueueClass, ValueClass, now,
};
use store::{IterateParams, Serialize, SerializeInfallible, U64_LEN, ValueKey};
use trc::ServerEvent;
use utils::BlobHash;

use super::{
    ArchivedMessage, ArchivedStatus, Domain, Message, MessageSource, QueueEnvelope, QueueId,
    QueuedMessage, QuotaKey, Recipient, Schedule, Status,
};

pub const LOCK_EXPIRY: u64 = 300;
pub const QUEUE_REFRESH: u64 = 300;

pub trait SmtpSpool: Sync + Send {
    fn new_message(
        &self,
        return_path: impl Into<String>,
        return_path_lcase: impl Into<String>,
        return_path_domain: impl Into<String>,
        span_id: u64,
    ) -> Message;

    fn next_event(&self) -> impl Future<Output = Vec<QueuedMessage>> + Send;

    fn try_lock_event(&self, queue_id: QueueId) -> impl Future<Output = bool> + Send;

    fn unlock_event(&self, queue_id: QueueId) -> impl Future<Output = ()> + Send;

    fn read_message(&self, id: QueueId) -> impl Future<Output = Option<Message>> + Send;

    fn read_message_archive(
        &self,
        id: QueueId,
    ) -> impl Future<Output = trc::Result<Option<Archive<AlignedBytes>>>> + Send;
}

impl SmtpSpool for Server {
    fn new_message(
        &self,
        return_path: impl Into<String>,
        return_path_lcase: impl Into<String>,
        return_path_domain: impl Into<String>,
        span_id: u64,
    ) -> Message {
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Message {
            queue_id: self.inner.data.queue_id_gen.generate(),
            span_id,
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

    async fn next_event(&self) -> Vec<QueuedMessage> {
        let now = now();
        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
            store::write::QueueEvent {
                due: 0,
                queue_id: 0,
            },
        )));
        let to_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
            store::write::QueueEvent {
                due: now + QUEUE_REFRESH,
                queue_id: u64::MAX,
            },
        )));

        let mut events = Vec::new();

        let result = self
            .store()
            .iterate(
                IterateParams::new(from_key, to_key).ascending().no_values(),
                |key, _| {
                    let due = key.deserialize_be_u64(0)?;
                    let queue_id = key.deserialize_be_u64(U64_LEN)?;

                    events.push(QueuedMessage { due, queue_id });

                    Ok(due <= now)
                },
            )
            .await;

        if let Err(err) = result {
            trc::error!(
                err.details("Failed to read queue.")
                    .caused_by(trc::location!())
            );
        }

        events
    }

    async fn try_lock_event(&self, queue_id: QueueId) -> bool {
        match self
            .in_memory_store()
            .try_lock(KV_LOCK_QUEUE_MESSAGE, &queue_id.to_be_bytes(), LOCK_EXPIRY)
            .await
        {
            Ok(result) => {
                if !result {
                    trc::event!(Queue(trc::QueueEvent::Locked), QueueId = queue_id,);
                }
                result
            }
            Err(err) => {
                trc::error!(
                    err.details("Failed to lock event.")
                        .caused_by(trc::location!())
                );
                false
            }
        }
    }

    async fn unlock_event(&self, queue_id: QueueId) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_QUEUE_MESSAGE, &queue_id.to_be_bytes())
            .await
        {
            trc::error!(
                err.details("Failed to unlock event.")
                    .caused_by(trc::location!())
            );
        }
    }

    async fn read_message(&self, id: QueueId) -> Option<Message> {
        match self.read_message_archive(id).await.and_then(|a| match a {
            Some(a) => a.deserialize::<Message>().map(Some),
            None => Ok(None),
        }) {
            Ok(Some(message)) => Some(message),
            Ok(None) => None,
            Err(err) => {
                trc::error!(
                    err.details("Failed to read message.")
                        .caused_by(trc::location!())
                );

                None
            }
        }
    }

    async fn read_message_archive(
        &self,
        id: QueueId,
    ) -> trc::Result<Option<Archive<AlignedBytes>>> {
        self.store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Queue(
                QueueClass::Message(id),
            )))
            .await
    }
}

impl Message {
    pub async fn queue(
        mut self,
        raw_headers: Option<&[u8]>,
        raw_message: &[u8],
        session_id: u64,
        server: &Server,
        source: MessageSource,
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
        self.blob_hash = BlobHash::generate(message.as_ref());

        // Generate id
        if self.size == 0 {
            self.size = message.len() as u64;
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
        if let Err(err) = server.store().write(batch.build_all()).await {
            trc::error!(
                err.details("Failed to write to store.")
                    .span_id(session_id)
                    .caused_by(trc::location!())
            );

            return false;
        }
        if let Err(err) = server
            .blob_store()
            .put_blob(self.blob_hash.as_slice(), message.as_ref())
            .await
        {
            trc::error!(
                err.details("Failed to write blob.")
                    .span_id(session_id)
                    .caused_by(trc::location!())
            );

            return false;
        }

        trc::event!(
            Queue(match source {
                MessageSource::Authenticated => trc::QueueEvent::QueueMessageAuthenticated,
                MessageSource::Unauthenticated => trc::QueueEvent::QueueMessage,
                MessageSource::Dsn => trc::QueueEvent::QueueDsn,
                MessageSource::Report => trc::QueueEvent::QueueReport,
                MessageSource::Autogenerated => trc::QueueEvent::QueueAutogenerated,
            }),
            SpanId = session_id,
            QueueId = self.queue_id,
            From = if !self.return_path.is_empty() {
                trc::Value::String(self.return_path.as_str().into())
            } else {
                trc::Value::String("<>".into())
            },
            To = self
                .recipients
                .iter()
                .map(|r| trc::Value::String(r.address_lcase.as_str().into()))
                .collect::<Vec<_>>(),
            Size = self.size,
            NextRetry = trc::Value::Timestamp(self.next_delivery_event()),
            NextDsn = trc::Value::Timestamp(self.next_dsn()),
            Expires = trc::Value::Timestamp(self.expires()),
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
                ValueClass::Queue(QueueClass::MessageEvent(store::write::QueueEvent {
                    due: self.next_event().unwrap_or_default(),
                    queue_id: self.queue_id,
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
                    id: self.queue_id,
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
                ValueClass::Queue(QueueClass::Message(self.queue_id)),
                match Archiver::new(self).serialize() {
                    Ok(data) => data,
                    Err(err) => {
                        trc::error!(
                            err.details("Failed to serialize message.")
                                .span_id(session_id)
                                .caused_by(trc::location!())
                        );
                        return false;
                    }
                },
            );

        if let Err(err) = server.store().write(batch.build_all()).await {
            trc::error!(
                err.details("Failed to write to store.")
                    .span_id(session_id)
                    .caused_by(trc::location!())
            );

            return false;
        }

        // Queue the message
        if server
            .inner
            .ipc
            .queue_tx
            .send(QueueEvent::Refresh)
            .await
            .is_err()
        {
            trc::event!(
                Server(ServerEvent::ThreadError),
                Reason = "Channel closed.",
                CausedBy = trc::location!(),
                SpanId = session_id,
            );
        }

        true
    }

    pub async fn add_recipient_parts(
        &mut self,
        rcpt: impl Into<String>,
        rcpt_lcase: impl Into<String>,
        rcpt_domain: impl Into<String>,
        server: &Server,
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

                let expires = server
                    .eval_if(
                        &server.core.smtp.queue.expire,
                        &QueueEnvelope::new(self, idx),
                        self.span_id,
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
            domain_idx: domain_idx as u32,
            address: rcpt.into(),
            address_lcase: rcpt_lcase.into(),
            status: Status::Scheduled,
            flags: 0,
            orcpt: None,
        });
    }

    pub async fn add_recipient(&mut self, rcpt: impl Into<String>, server: &Server) {
        let rcpt = rcpt.into();
        let rcpt_lcase = rcpt.to_lowercase();
        let rcpt_domain = rcpt_lcase.domain_part().to_string();
        self.add_recipient_parts(rcpt, rcpt_lcase, rcpt_domain, server)
            .await;
    }

    pub async fn save_changes(
        mut self,
        server: &Server,
        prev_event: Option<u64>,
        next_event: Option<u64>,
    ) -> bool {
        debug_assert!(prev_event.is_some() == next_event.is_some());

        // Release quota for completed deliveries
        let mut batch = BatchBuilder::new();
        self.release_quota(&mut batch);

        // Update message queue
        if let (Some(prev_event), Some(next_event)) = (prev_event, next_event) {
            batch
                .clear(ValueClass::Queue(QueueClass::MessageEvent(
                    store::write::QueueEvent {
                        due: prev_event,
                        queue_id: self.queue_id,
                    },
                )))
                .set(
                    ValueClass::Queue(QueueClass::MessageEvent(store::write::QueueEvent {
                        due: next_event,
                        queue_id: self.queue_id,
                    })),
                    0u64.serialize(),
                );
        }

        let span_id = self.span_id;
        batch.set(
            ValueClass::Queue(QueueClass::Message(self.queue_id)),
            match Archiver::new(self).serialize() {
                Ok(data) => data,
                Err(err) => {
                    trc::error!(
                        err.details("Failed to serialize message.")
                            .span_id(span_id)
                            .caused_by(trc::location!())
                    );
                    return false;
                }
            },
        );

        if let Err(err) = server.store().write(batch.build_all()).await {
            trc::error!(
                err.details("Failed to save changes.")
                    .span_id(span_id)
                    .caused_by(trc::location!())
            );
            false
        } else {
            true
        }
    }

    pub async fn remove(self, server: &Server, prev_event: u64) -> bool {
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
                id: self.queue_id,
            })
            .clear(ValueClass::Queue(QueueClass::MessageEvent(
                store::write::QueueEvent {
                    due: prev_event,
                    queue_id: self.queue_id,
                },
            )))
            .clear(ValueClass::Queue(QueueClass::Message(self.queue_id)));

        if let Err(err) = server.store().write(batch.build_all()).await {
            trc::error!(
                err.details("Failed to write to update queue.")
                    .span_id(self.span_id)
                    .caused_by(trc::location!())
            );
            false
        } else {
            true
        }
    }

    pub fn has_domain(&self, domains: &[String]) -> bool {
        self.domains.iter().any(|d| domains.contains(&d.domain))
            || self
                .return_path
                .rsplit_once('@')
                .is_some_and(|(_, domain)| domains.iter().any(|dd| dd == domain))
    }
}

impl ArchivedMessage {
    pub fn has_domain(&self, domains: &[String]) -> bool {
        self.domains
            .iter()
            .any(|d| domains.iter().any(|dd| dd == d.domain.as_str()))
            || self
                .return_path
                .rsplit_once('@')
                .is_some_and(|(_, domain)| domains.iter().any(|dd| dd == domain))
    }

    pub fn next_delivery_event(&self) -> u64 {
        let mut next_delivery = now();

        for (pos, domain) in self
            .domains
            .iter()
            .filter(|d| {
                matches!(
                    d.status,
                    ArchivedStatus::Scheduled | ArchivedStatus::TemporaryFailure(_)
                )
            })
            .enumerate()
        {
            if pos == 0 || domain.retry.due < next_delivery {
                next_delivery = domain.retry.due.into();
            }
        }

        next_delivery
    }
}
