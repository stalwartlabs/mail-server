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

use std::{
    collections::BinaryHeap,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use ahash::AHashMap;
use smtp_proto::Response;
use tokio::sync::mpsc;

use crate::core::{
    management::{self},
    QueueCore, SMTP,
};

use super::{
    DeliveryAttempt, Event, HostResponse, Message, OnHold, QueueId, Schedule, Status, WorkerResult,
    RCPT_STATUS_CHANGED,
};

#[derive(Debug)]
pub struct Queue {
    short_wait: Duration,
    long_wait: Duration,
    pub scheduled: BinaryHeap<Schedule<QueueId>>,
    pub on_hold: Vec<OnHold<QueueId>>,
    pub messages: AHashMap<QueueId, Box<Message>>,
}

impl SpawnQueue for mpsc::Receiver<Event> {
    fn spawn(mut self, core: Arc<SMTP>, mut queue: Queue) {
        tokio::spawn(async move {
            loop {
                let result = tokio::time::timeout(queue.wake_up_time(), self.recv()).await;

                // Deliver scheduled messages
                while let Some(message) = queue.next_due() {
                    DeliveryAttempt::from(message)
                        .try_deliver(core.clone(), &mut queue)
                        .await;
                }

                match result {
                    Ok(Some(event)) => match event {
                        Event::Queue(item) => {
                            // Deliver any concurrency limited messages
                            while let Some(message) = queue.next_on_hold() {
                                DeliveryAttempt::from(message)
                                    .try_deliver(core.clone(), &mut queue)
                                    .await;
                            }

                            if item.due <= Instant::now() {
                                DeliveryAttempt::from(item.inner)
                                    .try_deliver(core.clone(), &mut queue)
                                    .await;
                            } else {
                                queue.schedule(item);
                            }
                        }
                        Event::Done(result) => {
                            // A worker is done, try delivering concurrency limited messages
                            while let Some(message) = queue.next_on_hold() {
                                DeliveryAttempt::from(message)
                                    .try_deliver(core.clone(), &mut queue)
                                    .await;
                            }
                            match result {
                                WorkerResult::Done => (),
                                WorkerResult::Retry(schedule) => {
                                    queue.schedule(schedule);
                                }
                                WorkerResult::OnHold(on_hold) => {
                                    queue.on_hold(on_hold);
                                }
                            }
                        }
                        Event::Manage(request) => match request {
                            management::QueueRequest::List {
                                from,
                                to,
                                before,
                                after,
                                result_tx,
                            } => {
                                let mut result = Vec::with_capacity(queue.messages.len());
                                for message in queue.messages.values() {
                                    if from.as_ref().map_or(false, |from| {
                                        !message.return_path_lcase.contains(from)
                                    }) {
                                        continue;
                                    }
                                    if to.as_ref().map_or(false, |to| {
                                        !message
                                            .recipients
                                            .iter()
                                            .any(|rcpt| rcpt.address_lcase.contains(to))
                                    }) {
                                        continue;
                                    }

                                    if (before.is_some() || after.is_some())
                                        && !message.domains.iter().any(|domain| {
                                            matches!(
                                                &domain.status,
                                                Status::Scheduled | Status::TemporaryFailure(_)
                                            ) && match (&before, &after) {
                                                (Some(before), Some(after)) => {
                                                    domain.retry.due.lt(before)
                                                        && domain.retry.due.gt(after)
                                                }
                                                (Some(before), None) => domain.retry.due.lt(before),
                                                (None, Some(after)) => domain.retry.due.gt(after),
                                                (None, None) => false,
                                            }
                                        })
                                    {
                                        continue;
                                    }

                                    result.push(message.id);
                                }
                                result.sort_unstable_by_key(|id| *id & 0xFFFFFFFF);
                                let _ = result_tx.send(result);
                            }
                            management::QueueRequest::Status {
                                queue_ids,
                                result_tx,
                            } => {
                                let mut result = Vec::with_capacity(queue_ids.len());
                                for queue_id in queue_ids {
                                    result.push(
                                        queue
                                            .messages
                                            .get(&queue_id)
                                            .map(|message| message.as_ref().into()),
                                    );
                                }
                                let _ = result_tx.send(result);
                            }
                            management::QueueRequest::Cancel {
                                queue_ids,
                                item,
                                result_tx,
                            } => {
                                let mut result = Vec::with_capacity(queue_ids.len());
                                for queue_id in &queue_ids {
                                    let mut found = false;
                                    if let Some(item) = &item {
                                        if let Some(message) = queue.messages.get_mut(queue_id) {
                                            // Cancel delivery for all recipients that match
                                            for rcpt in &mut message.recipients {
                                                if rcpt.address_lcase.contains(item) {
                                                    rcpt.flags |= RCPT_STATUS_CHANGED;
                                                    rcpt.status = Status::Completed(HostResponse {
                                                        hostname: String::new(),
                                                        response: Response {
                                                            code: 0,
                                                            esc: [0, 0, 0],
                                                            message: "Delivery canceled."
                                                                .to_string(),
                                                        },
                                                    });
                                                    found = true;
                                                }
                                            }
                                            if found {
                                                // Mark as completed domains without any pending deliveries
                                                for (domain_idx, domain) in
                                                    message.domains.iter_mut().enumerate()
                                                {
                                                    if matches!(
                                                        domain.status,
                                                        Status::TemporaryFailure(_)
                                                            | Status::Scheduled
                                                    ) {
                                                        let mut total_rcpt = 0;
                                                        let mut total_completed = 0;

                                                        for rcpt in &message.recipients {
                                                            if rcpt.domain_idx == domain_idx {
                                                                total_rcpt += 1;
                                                                if matches!(
                                                                    rcpt.status,
                                                                    Status::PermanentFailure(_)
                                                                        | Status::Completed(_)
                                                                ) {
                                                                    total_completed += 1;
                                                                }
                                                            }
                                                        }

                                                        if total_rcpt == total_completed {
                                                            domain.status = Status::Completed(());
                                                            domain.changed = true;
                                                        }
                                                    }
                                                }

                                                // Delete message if there are no pending deliveries
                                                if message.domains.iter().any(|domain| {
                                                    matches!(
                                                        domain.status,
                                                        Status::TemporaryFailure(_)
                                                            | Status::Scheduled
                                                    )
                                                }) {
                                                    message.save_changes().await;
                                                } else {
                                                    message.remove().await;
                                                    queue.messages.remove(queue_id);
                                                }
                                            }
                                        }
                                    } else if let Some(message) = queue.messages.remove(queue_id) {
                                        message.remove().await;
                                        found = true;
                                    }
                                    result.push(found);
                                }
                                let _ = result_tx.send(result);
                            }
                            management::QueueRequest::Retry {
                                queue_ids,
                                item,
                                time,
                                result_tx,
                            } => {
                                let mut result = Vec::with_capacity(queue_ids.len());
                                for queue_id in &queue_ids {
                                    let mut found = false;
                                    if let Some(message) = queue.messages.get_mut(queue_id) {
                                        for domain in &mut message.domains {
                                            if matches!(
                                                domain.status,
                                                Status::Scheduled | Status::TemporaryFailure(_)
                                            ) && item
                                                .as_ref()
                                                .map_or(true, |item| domain.domain.contains(item))
                                            {
                                                domain.retry.due = time;
                                                if domain.expires > time {
                                                    domain.expires = time + Duration::from_secs(10);
                                                }
                                                domain.changed = true;
                                                found = true;
                                            }
                                        }

                                        if found {
                                            queue.on_hold.retain(|oh| &oh.message != queue_id);
                                            message.save_changes().await;
                                            if let Some(next_event) = message.next_event() {
                                                queue.scheduled.push(Schedule {
                                                    due: next_event,
                                                    inner: *queue_id,
                                                });
                                            }
                                        }
                                    }
                                    result.push(found);
                                }
                                let _ = result_tx.send(result);
                            }
                        },
                        Event::Stop => break,
                    },
                    Ok(None) => break,
                    Err(_) => (),
                }
            }
        });
    }
}

impl Queue {
    pub fn schedule(&mut self, message: Schedule<Box<Message>>) {
        self.scheduled.push(Schedule {
            due: message.due,
            inner: message.inner.id,
        });
        self.messages.insert(message.inner.id, message.inner);
    }

    pub fn on_hold(&mut self, message: OnHold<Box<Message>>) {
        self.on_hold.push(OnHold {
            next_due: message.next_due,
            limiters: message.limiters,
            message: message.message.id,
        });
        self.messages.insert(message.message.id, message.message);
    }

    pub fn next_due(&mut self) -> Option<Box<Message>> {
        let item = self.scheduled.peek()?;
        if item.due <= Instant::now() {
            self.scheduled
                .pop()
                .and_then(|i| self.messages.remove(&i.inner))
        } else {
            None
        }
    }

    pub fn next_on_hold(&mut self) -> Option<Box<Message>> {
        let now = Instant::now();
        self.on_hold
            .iter()
            .position(|o| {
                o.limiters
                    .iter()
                    .any(|l| l.concurrent.load(Ordering::Relaxed) < l.max_concurrent)
                    || o.next_due.map_or(false, |due| due <= now)
            })
            .and_then(|pos| self.messages.remove(&self.on_hold.remove(pos).message))
    }

    pub fn wake_up_time(&self) -> Duration {
        self.scheduled
            .peek()
            .map(|item| {
                item.due
                    .checked_duration_since(Instant::now())
                    .unwrap_or(self.short_wait)
            })
            .unwrap_or(self.long_wait)
    }
}

impl Message {
    pub fn next_event(&self) -> Option<Instant> {
        let mut next_event = Instant::now();
        let mut has_events = false;

        for domain in &self.domains {
            if matches!(
                domain.status,
                Status::Scheduled | Status::TemporaryFailure(_)
            ) {
                if !has_events || domain.retry.due < next_event {
                    next_event = domain.retry.due;
                    has_events = true;
                }
                if domain.notify.due < next_event {
                    next_event = domain.notify.due;
                }
                if domain.expires < next_event {
                    next_event = domain.expires;
                }
            }
        }

        if has_events {
            next_event.into()
        } else {
            None
        }
    }

    pub fn next_delivery_event(&self) -> Instant {
        let mut next_delivery = Instant::now();

        for (pos, domain) in self
            .domains
            .iter()
            .filter(|d| matches!(d.status, Status::Scheduled | Status::TemporaryFailure(_)))
            .enumerate()
        {
            if pos == 0 || domain.retry.due < next_delivery {
                next_delivery = domain.retry.due;
            }
        }

        next_delivery
    }

    pub fn next_event_after(&self, instant: Instant) -> Option<Instant> {
        let mut next_event = None;

        for domain in &self.domains {
            if matches!(
                domain.status,
                Status::Scheduled | Status::TemporaryFailure(_)
            ) {
                if domain.retry.due > instant
                    && next_event
                        .as_ref()
                        .map_or(true, |ne| domain.retry.due.lt(ne))
                {
                    next_event = domain.retry.due.into();
                }
                if domain.notify.due > instant
                    && next_event
                        .as_ref()
                        .map_or(true, |ne| domain.notify.due.lt(ne))
                {
                    next_event = domain.notify.due.into();
                }
                if domain.expires > instant
                    && next_event.as_ref().map_or(true, |ne| domain.expires.lt(ne))
                {
                    next_event = domain.expires.into();
                }
            }
        }

        next_event
    }
}

impl QueueCore {
    pub async fn read_queue(&self) -> Queue {
        let mut queue = Queue::default();
        let mut messages = Vec::new();

        for path in self
            .config
            .path
            .if_then
            .iter()
            .map(|t| &t.then)
            .chain([&self.config.path.default])
        {
            let mut dir = match tokio::fs::read_dir(path).await {
                Ok(dir) => dir,
                Err(_) => continue,
            };
            loop {
                match dir.next_entry().await {
                    Ok(Some(file)) => {
                        let file = file.path();
                        if file.is_dir() {
                            match tokio::fs::read_dir(&file).await {
                                Ok(mut dir) => {
                                    let file_ = file;
                                    loop {
                                        match dir.next_entry().await {
                                            Ok(Some(file)) => {
                                                let file = file.path();
                                                if file.extension().map_or(false, |e| e == "msg") {
                                                    messages.push(tokio::spawn(
                                                        Message::from_path(file),
                                                    ));
                                                }
                                            }
                                            Ok(None) => break,
                                            Err(err) => {
                                                tracing::warn!(
                                                    "Failed to read queue directory {}: {}",
                                                    file_.display(),
                                                    err
                                                );
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    tracing::warn!(
                                        "Failed to read queue directory {}: {}",
                                        file.display(),
                                        err
                                    )
                                }
                            };
                        } else if file.extension().map_or(false, |e| e == "msg") {
                            messages.push(tokio::spawn(Message::from_path(file)));
                        }
                    }
                    Ok(None) => {
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "Failed to read queue directory {}: {}",
                            path.display(),
                            err
                        );
                        break;
                    }
                }
            }
        }

        // Join all futures
        for message in messages {
            match message.await {
                Ok(Ok(mut message)) => {
                    // Reserve quota
                    self.has_quota(&mut message).await;

                    // Schedule message
                    queue.schedule(Schedule {
                        due: message.next_event().unwrap_or_else(|| {
                            tracing::warn!(
                                context = "queue",
                                event = "warn",
                                "No due events found for message {}",
                                message.path.display()
                            );
                            Instant::now()
                        }),
                        inner: Box::new(message),
                    });
                }
                Ok(Err(err)) => {
                    tracing::warn!(
                        context = "queue",
                        event = "error",
                        "Queue startup error: {}",
                        err
                    );
                }
                Err(err) => {
                    tracing::error!("Join error while starting queue: {}", err);
                }
            }
        }

        queue
    }
}

impl Default for Queue {
    fn default() -> Self {
        Queue {
            short_wait: Duration::from_millis(1),
            long_wait: Duration::from_secs(86400 * 365),
            scheduled: BinaryHeap::with_capacity(128),
            on_hold: Vec::with_capacity(128),
            messages: AHashMap::with_capacity(128),
        }
    }
}

pub trait SpawnQueue {
    fn spawn(self, core: Arc<SMTP>, queue: Queue);
}
