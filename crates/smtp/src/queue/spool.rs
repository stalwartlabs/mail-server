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
use mail_auth::common::base32::Base32Writer;
use mail_auth::common::headers::Writer;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Instant;
use std::time::{Duration, SystemTime};
use tokio::fs::OpenOptions;
use tokio::{fs, io::AsyncWriteExt};

use crate::config::QueueConfig;
use crate::core::QueueCore;

use super::{Domain, Event, Message, Recipient, Schedule, SimpleEnvelope, Status};

impl QueueCore {
    pub async fn queue_message(
        &self,
        mut message: Box<Message>,
        raw_headers: Option<&[u8]>,
        raw_message: &[u8],
        span: &tracing::Span,
    ) -> bool {
        // Generate id
        if message.id == 0 {
            message.id = self.queue_id();
        }
        if message.size == 0 {
            message.size = raw_message.len() + raw_headers.as_ref().map_or(0, |h| h.len());
        }

        // Build path
        message.path = self.config.path.eval(message.as_ref()).await.clone();
        let hash = *self.config.hash.eval(message.as_ref()).await;
        if hash > 0 {
            message.path.push((message.id % hash).to_string());
        }
        let _ = fs::create_dir(&message.path).await;

        // Encode file name
        let mut encoder = Base32Writer::with_capacity(20);
        encoder.write(&message.id.to_le_bytes()[..]);
        encoder.write(&(message.size as u32).to_le_bytes()[..]);
        let mut file = encoder.finalize();
        file.push_str(".msg");
        message.path.push(file);

        // Serialize metadata
        let metadata = message.serialize();

        // Save message
        let mut file = match fs::File::create(&message.path).await {
            Ok(file) => file,
            Err(err) => {
                tracing::error!(
                    parent: span,
                    context = "queue",
                    event = "error",
                    "Failed to create file {}: {}",
                    message.path.display(),
                    err
                );
                return false;
            }
        };

        let iter = if let Some(raw_headers) = raw_headers {
            [raw_headers, raw_message, &metadata].into_iter()
        } else {
            [raw_message, &metadata, b""].into_iter()
        };

        for bytes in iter {
            if !bytes.is_empty() {
                if let Err(err) = file.write_all(bytes).await {
                    tracing::error!(
                        parent: span,
                        context = "queue",
                        event = "error",
                        "Failed to write to file {}: {}",
                        message.path.display(),
                        err
                    );
                    return false;
                }
            }
        }
        if let Err(err) = file.flush().await {
            tracing::error!(
                parent: span,
                context = "queue",
                event = "error",
                "Failed to flush file {}: {}",
                message.path.display(),
                err
            );
            return false;
        }

        tracing::info!(
            parent: span,
            context = "queue",
            event = "scheduled",
            id = message.id,
            from = if !message.return_path.is_empty() {
                message.return_path.as_str()
            } else {
                "<>"
            },
            nrcpts = message.recipients.len(),
            size = message.size,
            "Message queued for delivery."
        );

        // Queue the message
        if self
            .tx
            .send(Event::Queue(Schedule {
                due: message.next_event().unwrap(),
                inner: message,
            }))
            .await
            .is_err()
        {
            tracing::warn!(
                parent: span,
                context = "queue",
                event = "error",
                "Queue channel closed: Message queued but won't be sent until next restart."
            );
        }

        true
    }

    pub fn queue_id(&self) -> u64 {
        (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            .saturating_sub(946684800)
            & 0xFFFFFFFF)
            | (self.id_seq.fetch_add(1, Ordering::Relaxed) as u64) << 32
    }
}

impl Message {
    pub fn new_boxed(
        return_path: impl Into<String>,
        return_path_lcase: impl Into<String>,
        return_path_domain: impl Into<String>,
    ) -> Box<Message> {
        Box::new(Message {
            id: 0,
            path: PathBuf::new(),
            created: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            return_path: return_path.into(),
            return_path_lcase: return_path_lcase.into(),
            return_path_domain: return_path_domain.into(),
            recipients: Vec::with_capacity(1),
            domains: Vec::with_capacity(1),
            flags: 0,
            env_id: None,
            priority: 0,
            size: 0,
            queue_refs: vec![],
        })
    }

    pub async fn add_recipient_parts(
        &mut self,
        rcpt: impl Into<String>,
        rcpt_lcase: impl Into<String>,
        rcpt_domain: impl Into<String>,
        config: &QueueConfig,
    ) {
        let rcpt_domain = rcpt_domain.into();
        let domain_idx =
            if let Some(idx) = self.domains.iter().position(|d| d.domain == rcpt_domain) {
                idx
            } else {
                let idx = self.domains.len();
                let expires = *config
                    .expire
                    .eval(&SimpleEnvelope::new(self, &rcpt_domain))
                    .await;
                self.domains.push(Domain {
                    domain: rcpt_domain,
                    retry: Schedule::now(),
                    notify: Schedule::later(expires + Duration::from_secs(10)),
                    expires: Instant::now() + expires,
                    status: Status::Scheduled,
                    changed: false,
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

    pub async fn add_recipient(&mut self, rcpt: impl Into<String>, config: &QueueConfig) {
        let rcpt = rcpt.into();
        let rcpt_lcase = rcpt.to_lowercase();
        let rcpt_domain = rcpt_lcase.domain_part().to_string();
        self.add_recipient_parts(rcpt, rcpt_lcase, rcpt_domain, config)
            .await;
    }

    pub async fn save_changes(&mut self) {
        let buf = self.serialize_changes();
        if !buf.is_empty() {
            let err = match OpenOptions::new().append(true).open(&self.path).await {
                Ok(mut file) => match file.write_all(&buf).await {
                    Ok(_) => return,
                    Err(err) => err,
                },
                Err(err) => err,
            };
            tracing::error!(
                context = "queue",
                event = "error",
                "Failed to write to {}: {}",
                self.path.display(),
                err
            );
        }
    }

    pub async fn remove(&self) {
        if let Err(err) = fs::remove_file(&self.path).await {
            tracing::error!(
                context = "queue",
                event = "error",
                "Failed to delete queued message {}: {}",
                self.path.display(),
                err
            );
        }
    }
}
