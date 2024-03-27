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

use std::time::Duration;

use store::{
    write::{key::DeserializeBigEndian, Bincode, QueueClass, QueueEvent, ReportEvent, ValueClass},
    Deserialize, IterateParams, ValueKey, U64_LEN,
};
use tokio::sync::mpsc::error::TryRecvError;

use smtp::{
    core::SMTP,
    queue::{self, spool::QueueEventLock, DeliveryAttempt, Message, OnHold, QueueId},
    reporting::{self, DmarcEvent, TlsEvent},
};

use super::{QueueReceiver, ReportReceiver};

pub mod antispam;
pub mod auth;
pub mod basic;
pub mod data;
pub mod dmarc;
pub mod ehlo;
pub mod limits;
pub mod mail;
pub mod milter;
pub mod rcpt;
pub mod rewrite;
pub mod scripts;
pub mod sign;
pub mod throttle;
pub mod vrfy;

impl QueueReceiver {
    pub async fn read_event(&mut self) -> queue::Event {
        match tokio::time::timeout(Duration::from_millis(100), self.queue_rx.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => panic!("Channel closed."),
            Err(_) => panic!("No queue event received."),
        }
    }

    pub async fn try_read_event(&mut self) -> Option<queue::Event> {
        match tokio::time::timeout(Duration::from_millis(100), self.queue_rx.recv()).await {
            Ok(Some(event)) => Some(event),
            Ok(None) => panic!("Channel closed."),
            Err(_) => None,
        }
    }

    pub fn assert_no_events(&mut self) {
        match self.queue_rx.try_recv() {
            Err(TryRecvError::Empty) => (),
            Ok(event) => panic!("Expected empty queue but got {event:?}"),
            Err(err) => panic!("Queue error: {err:?}"),
        }
    }

    pub async fn assert_queue_is_empty(&self) {
        assert_eq!(self.read_queued_messages().await, vec![]);
        assert_eq!(self.read_queued_events().await, vec![]);
    }

    pub async fn assert_report_is_empty(&self) {
        assert_eq!(self.read_report_events().await, vec![]);

        for (from_key, to_key) in [
            (
                ValueKey::from(ValueClass::Queue(QueueClass::TlsReportEvent(ReportEvent {
                    due: 0,
                    policy_hash: 0,
                    seq_id: 0,
                    domain: String::new(),
                }))),
                ValueKey::from(ValueClass::Queue(QueueClass::TlsReportEvent(ReportEvent {
                    due: u64::MAX,
                    policy_hash: 0,
                    seq_id: 0,
                    domain: String::new(),
                }))),
            ),
            (
                ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportEvent(
                    ReportEvent {
                        due: 0,
                        policy_hash: 0,
                        seq_id: 0,
                        domain: String::new(),
                    },
                ))),
                ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportEvent(
                    ReportEvent {
                        due: u64::MAX,
                        policy_hash: 0,
                        seq_id: 0,
                        domain: String::new(),
                    },
                ))),
            ),
        ] {
            self.store
                .iterate(
                    IterateParams::new(from_key, to_key).ascending().no_values(),
                    |key, _| {
                        panic!("Unexpected report event: {key:?}");
                    },
                )
                .await
                .unwrap();
        }
    }

    pub async fn expect_message(&mut self) -> Message {
        self.read_event().await.assert_reload();
        self.last_queued_message().await
    }

    pub async fn consume_message(&mut self, core: &SMTP) -> Message {
        self.read_event().await.assert_reload();
        let message = self.last_queued_message().await;
        message
            .clone()
            .remove(core, self.last_queued_due().await)
            .await;
        message
    }

    pub async fn expect_message_then_deliver(&mut self) -> DeliveryAttempt {
        let message = self.expect_message().await;

        self.delivery_attempt(message.id).await
    }

    pub async fn delivery_attempt(&mut self, queue_id: u64) -> DeliveryAttempt {
        DeliveryAttempt::new(QueueEventLock {
            due: self.message_due(queue_id).await,
            queue_id,
            lock_expiry: 0,
        })
    }

    pub async fn read_queued_events(&self) -> Vec<QueueEvent> {
        let mut events = Vec::new();

        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
            due: 0,
            queue_id: 0,
        })));
        let to_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
            due: u64::MAX,
            queue_id: u64::MAX,
        })));

        self.store
            .iterate(
                IterateParams::new(from_key, to_key).ascending().no_values(),
                |key, _| {
                    events.push(QueueEvent {
                        due: key.deserialize_be_u64(1)?,
                        queue_id: key.deserialize_be_u64(U64_LEN + 1)?,
                    });
                    Ok(true)
                },
            )
            .await
            .unwrap();

        events
    }

    pub async fn read_queued_messages(&self) -> Vec<Message> {
        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(0)));
        let to_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(u64::MAX)));
        let mut messages = Vec::new();

        self.store
            .iterate(
                IterateParams::new(from_key, to_key).descending(),
                |key, value| {
                    let value = Bincode::<Message>::deserialize(value)?;
                    assert_eq!(key.deserialize_be_u64(1)?, value.inner.id);
                    messages.push(value.inner);
                    Ok(true)
                },
            )
            .await
            .unwrap();

        messages
    }

    pub async fn read_report_events(&self) -> Vec<QueueClass> {
        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportHeader(
            ReportEvent {
                due: 0,
                policy_hash: 0,
                seq_id: 0,
                domain: String::new(),
            },
        )));
        let to_key = ValueKey::from(ValueClass::Queue(QueueClass::TlsReportHeader(
            ReportEvent {
                due: u64::MAX,
                policy_hash: 0,
                seq_id: 0,
                domain: String::new(),
            },
        )));

        let mut events = Vec::new();
        self.store
            .iterate(
                IterateParams::new(from_key, to_key).ascending().no_values(),
                |key, _| {
                    let event = ReportEvent::deserialize(key)?;
                    // Skip lock
                    if event.seq_id != 0 {
                        events.push(if *key.last().unwrap() == 0 {
                            QueueClass::DmarcReportHeader(event)
                        } else {
                            QueueClass::TlsReportHeader(event)
                        });
                    }
                    Ok(true)
                },
            )
            .await
            .unwrap();
        events
    }

    pub async fn last_queued_message(&self) -> Message {
        self.read_queued_messages()
            .await
            .into_iter()
            .next()
            .expect("No messages found in queue")
    }

    pub async fn last_queued_due(&self) -> u64 {
        self.message_due(self.last_queued_message().await.id).await
    }

    pub async fn message_due(&self, queue_id: QueueId) -> u64 {
        self.read_queued_events()
            .await
            .iter()
            .find_map(|event| {
                if event.queue_id == queue_id {
                    Some(event.due)
                } else {
                    None
                }
            })
            .expect("No event found in queue for message")
    }

    pub async fn clear_queue(&self, core: &SMTP) {
        for message in self.read_queued_messages().await {
            let due = self.message_due(message.id).await;
            message.remove(core, due).await;
        }
    }
}

impl ReportReceiver {
    pub async fn read_report(&mut self) -> reporting::Event {
        match tokio::time::timeout(Duration::from_millis(100), self.report_rx.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => panic!("Channel closed."),
            Err(_) => panic!("No report event received."),
        }
    }

    pub async fn try_read_report(&mut self) -> Option<reporting::Event> {
        match tokio::time::timeout(Duration::from_millis(100), self.report_rx.recv()).await {
            Ok(Some(event)) => Some(event),
            Ok(None) => panic!("Channel closed."),
            Err(_) => None,
        }
    }
    pub fn assert_no_reports(&mut self) {
        match self.report_rx.try_recv() {
            Err(TryRecvError::Empty) => (),
            Ok(event) => panic!("Expected no reports but got {event:?}"),
            Err(err) => panic!("Report error: {err:?}"),
        }
    }
}

pub trait TestQueueEvent {
    fn assert_reload(self);
    fn unwrap_on_hold(self) -> OnHold<QueueEventLock>;
}

impl TestQueueEvent for queue::Event {
    fn assert_reload(self) {
        match self {
            queue::Event::Reload => (),
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    fn unwrap_on_hold(self) -> OnHold<QueueEventLock> {
        match self {
            queue::Event::OnHold(value) => value,
            e => panic!("Unexpected event: {e:?}"),
        }
    }
}

pub trait TestReportingEvent {
    fn unwrap_dmarc(self) -> Box<DmarcEvent>;
    fn unwrap_tls(self) -> Box<TlsEvent>;
}

impl TestReportingEvent for reporting::Event {
    fn unwrap_dmarc(self) -> Box<DmarcEvent> {
        match self {
            reporting::Event::Dmarc(event) => event,
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    fn unwrap_tls(self) -> Box<TlsEvent> {
        match self {
            reporting::Event::Tls(event) => event,
            e => panic!("Unexpected event: {e:?}"),
        }
    }
}

#[allow(async_fn_in_trait)]
pub trait TestMessage {
    async fn read_message(&self, core: &QueueReceiver) -> String;
    async fn read_lines(&self, core: &QueueReceiver) -> Vec<String>;
}

impl TestMessage for Message {
    async fn read_message(&self, core: &QueueReceiver) -> String {
        String::from_utf8(
            core.blob_store
                .get_blob(self.blob_hash.as_slice(), 0..usize::MAX)
                .await
                .unwrap()
                .expect("Message blob not found"),
        )
        .unwrap()
    }

    async fn read_lines(&self, core: &QueueReceiver) -> Vec<String> {
        self.read_message(core)
            .await
            .split('\n')
            .map(|l| l.to_string())
            .collect()
    }
}
