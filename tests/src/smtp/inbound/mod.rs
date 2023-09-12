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

use tokio::sync::mpsc::error::TryRecvError;

use smtp::{
    queue::{self, Message, OnHold, Schedule, WorkerResult},
    reporting::{self, DmarcEvent, TlsEvent},
};

use super::{QueueReceiver, ReportReceiver};

pub mod antispam;
pub mod auth;
pub mod basic;
pub mod data;
pub mod dmarc;
pub mod dnsrbl;
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
    pub fn assert_empty_queue(&mut self) {
        match self.queue_rx.try_recv() {
            Err(TryRecvError::Empty) => (),
            Ok(event) => panic!("Expected empty queue but got {event:?}"),
            Err(err) => panic!("Queue error: {err:?}"),
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
    fn unwrap_message(self) -> Box<Message>;
    fn unwrap_schedule(self) -> Schedule<Box<Message>>;
    fn unwrap_result(self) -> WorkerResult;
    fn unwrap_done(self);
    fn unwrap_on_hold(self) -> OnHold<Box<Message>>;
    fn unwrap_retry(self) -> Schedule<Box<Message>>;
}

impl TestQueueEvent for queue::Event {
    fn unwrap_message(self) -> Box<Message> {
        match self {
            queue::Event::Queue(message) => message.inner,
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    fn unwrap_schedule(self) -> Schedule<Box<Message>> {
        match self {
            queue::Event::Queue(message) => message,
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    fn unwrap_result(self) -> WorkerResult {
        match self {
            queue::Event::Done(result) => result,
            queue::Event::Queue(message) => {
                panic!("Unexpected message: {}", message.inner.read_message());
            }
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    fn unwrap_done(self) {
        match self {
            queue::Event::Done(WorkerResult::Done) => (),
            queue::Event::Queue(message) => {
                panic!("Unexpected message: {}", message.inner.read_message());
            }
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    fn unwrap_on_hold(self) -> OnHold<Box<Message>> {
        match self {
            queue::Event::Done(WorkerResult::OnHold(value)) => value,
            queue::Event::Queue(message) => {
                panic!("Unexpected message: {}", message.inner.read_message());
            }
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    fn unwrap_retry(self) -> Schedule<Box<Message>> {
        match self {
            queue::Event::Done(WorkerResult::Retry(value)) => value,
            queue::Event::Queue(message) => {
                panic!("Unexpected message: {}", message.inner.read_message());
            }
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

pub trait TestMessage {
    fn read_message(&self) -> String;
    fn read_lines(&self) -> Vec<String>;
}

impl TestMessage for Message {
    fn read_message(&self) -> String {
        let mut buf = vec![0u8; self.size];
        let mut file = std::fs::File::open(&self.path).unwrap();
        std::io::Read::read_exact(&mut file, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn read_lines(&self) -> Vec<String> {
        self.read_message()
            .split('\n')
            .map(|l| l.to_string())
            .collect()
    }
}
