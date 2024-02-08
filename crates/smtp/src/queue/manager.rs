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

use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use store::write::{now, BatchBuilder, QueueClass, QueueEvent, ValueClass};
use tokio::sync::mpsc;

use crate::core::SMTP;

use super::{DeliveryAttempt, Event, Message, OnHold, Status};

pub(crate) const SHORT_WAIT: Duration = Duration::from_millis(1);
pub(crate) const LONG_WAIT: Duration = Duration::from_secs(86400 * 365);

#[derive(Debug)]
pub struct Queue {
    pub on_hold: Vec<OnHold<QueueEvent>>,
}

impl SpawnQueue for mpsc::Receiver<Event> {
    fn spawn(mut self, core: Arc<SMTP>) {
        tokio::spawn(async move {
            let mut queue = Queue::default();
            let mut next_wake_up = SHORT_WAIT;

            loop {
                let on_hold = match tokio::time::timeout(next_wake_up, self.recv()).await {
                    Ok(Some(Event::OnHold(on_hold))) => on_hold.into(),
                    Ok(Some(Event::Stop)) | Ok(None) => {
                        break;
                    }
                    _ => None,
                };

                // Deliver any concurrency limited messages
                let mut delete_events = Vec::new();
                while let Some(queue_event) = queue.next_on_hold() {
                    if let Some(message) = core.read_message(queue_event.queue_id).await {
                        DeliveryAttempt::new(message, queue_event)
                            .try_deliver(core.clone())
                            .await;
                    } else {
                        delete_events.push(queue_event);
                    }
                }

                // Deliver scheduled messages
                let now = now();
                next_wake_up = LONG_WAIT;
                for queue_event in core.next_event().await {
                    if queue_event.due <= now {
                        if let Some(message) = core.read_message(queue_event.queue_id).await {
                            DeliveryAttempt::new(message, queue_event)
                                .try_deliver(core.clone())
                                .await;
                        } else {
                            delete_events.push(queue_event);
                        }
                    } else {
                        next_wake_up = Duration::from_secs(queue_event.due - now);
                    }
                }

                // Delete unlinked events
                if !delete_events.is_empty() {
                    let core = core.clone();
                    tokio::spawn(async move {
                        let mut batch = BatchBuilder::new();
                        for queue_event in delete_events {
                            batch.clear(ValueClass::Queue(QueueClass::MessageEvent(queue_event)));
                        }
                        let _ = core.shared.default_data_store.write(batch.build()).await;
                    });
                }

                // Add message on hold
                if let Some(on_hold) = on_hold {
                    queue.on_hold(on_hold);
                }
            }
        });
    }
}

impl Queue {
    pub fn on_hold(&mut self, message: OnHold<QueueEvent>) {
        self.on_hold.push(OnHold {
            next_due: message.next_due,
            limiters: message.limiters,
            message: message.message,
        });
    }

    pub fn next_on_hold(&mut self) -> Option<QueueEvent> {
        let now = now();
        self.on_hold
            .iter()
            .position(|o| {
                o.limiters
                    .iter()
                    .any(|l| l.concurrent.load(Ordering::Relaxed) < l.max_concurrent)
                    || o.next_due.map_or(false, |due| due <= now)
            })
            .map(|pos| self.on_hold.remove(pos).message)
    }
}

impl Message {
    pub fn next_event(&self) -> Option<u64> {
        let mut next_event = now();
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

    pub fn next_delivery_event(&self) -> u64 {
        let mut next_delivery = now();

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

    pub fn next_event_after(&self, instant: u64) -> Option<u64> {
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

impl Default for Queue {
    fn default() -> Self {
        Queue {
            on_hold: Vec::with_capacity(128),
        }
    }
}

pub trait SpawnQueue {
    fn spawn(self, core: Arc<SMTP>);
}
