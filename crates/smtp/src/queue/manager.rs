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

use std::{sync::atomic::Ordering, time::Duration};

use store::write::now;
use tokio::sync::mpsc;

use crate::core::{SmtpInstance, SMTP};

use super::{spool::QueueEventLock, DeliveryAttempt, Event, Message, OnHold, Status};

pub(crate) const SHORT_WAIT: Duration = Duration::from_millis(1);
pub(crate) const LONG_WAIT: Duration = Duration::from_secs(86400 * 365);

pub struct Queue {
    pub core: SmtpInstance,
    pub on_hold: Vec<OnHold<QueueEventLock>>,
    pub next_wake_up: Duration,
}

impl SpawnQueue for mpsc::Receiver<Event> {
    fn spawn(mut self, core: SmtpInstance) {
        tokio::spawn(async move {
            let mut queue = Queue::new(core);

            loop {
                let on_hold = match tokio::time::timeout(queue.next_wake_up, self.recv()).await {
                    Ok(Some(Event::OnHold(on_hold))) => on_hold.into(),
                    Ok(Some(Event::Stop)) | Ok(None) => {
                        break;
                    }
                    _ => None,
                };

                queue.process_events().await;

                // Add message on hold
                if let Some(on_hold) = on_hold {
                    queue.on_hold(on_hold);
                }
            }
        });
    }
}

impl Queue {
    pub fn new(core: SmtpInstance) -> Self {
        Queue {
            core,
            on_hold: Vec::with_capacity(128),
            next_wake_up: SHORT_WAIT,
        }
    }

    pub async fn process_events(&mut self) {
        // Deliver any concurrency limited messages
        let core = SMTP::from(self.core.clone());
        while let Some(queue_event) = self.next_on_hold() {
            DeliveryAttempt::new(queue_event)
                .try_deliver(core.clone())
                .await;
        }

        // Deliver scheduled messages
        let now = now();
        self.next_wake_up = LONG_WAIT;
        for queue_event in core.next_event().await {
            if queue_event.due <= now {
                DeliveryAttempt::new(queue_event)
                    .try_deliver(core.clone())
                    .await;
            } else {
                self.next_wake_up = Duration::from_secs(queue_event.due - now);
            }
        }
    }

    pub fn on_hold(&mut self, message: OnHold<QueueEventLock>) {
        self.on_hold.push(OnHold {
            next_due: message.next_due,
            limiters: message.limiters,
            message: message.message,
        });
    }

    pub fn next_on_hold(&mut self) -> Option<QueueEventLock> {
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

    pub fn next_dsn(&self) -> u64 {
        let mut next_dsn = now();

        for (pos, domain) in self
            .domains
            .iter()
            .filter(|d| matches!(d.status, Status::Scheduled | Status::TemporaryFailure(_)))
            .enumerate()
        {
            if pos == 0 || domain.notify.due < next_dsn {
                next_dsn = domain.notify.due;
            }
        }

        next_dsn
    }

    pub fn expires(&self) -> u64 {
        let mut expires = now();

        for (pos, domain) in self
            .domains
            .iter()
            .filter(|d| matches!(d.status, Status::Scheduled | Status::TemporaryFailure(_)))
            .enumerate()
        {
            if pos == 0 || domain.expires < expires {
                expires = domain.expires;
            }
        }

        expires
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

pub trait SpawnQueue {
    fn spawn(self, core: SmtpInstance);
}
