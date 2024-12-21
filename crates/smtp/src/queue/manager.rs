/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use ahash::AHashSet;
use common::{
    core::BuildServer,
    ipc::{OnHold, QueueEvent, QueuedMessage},
    Inner,
};
use store::write::now;
use tokio::sync::mpsc;

use super::{
    spool::{SmtpSpool, QUEUE_REFRESH},
    DeliveryAttempt, Message, QueueId, Status,
};

pub struct Queue {
    pub core: Arc<Inner>,
    pub on_hold: Vec<OnHold<QueuedMessage>>,
    pub in_flight: AHashSet<QueueId>,
    pub next_wake_up: Instant,
    pub rx: mpsc::Receiver<QueueEvent>,
}

impl SpawnQueue for mpsc::Receiver<QueueEvent> {
    fn spawn(self, core: Arc<Inner>) {
        tokio::spawn(async move {
            Queue::new(core, self).start().await;
        });
    }
}

impl Queue {
    pub fn new(core: Arc<Inner>, rx: mpsc::Receiver<QueueEvent>) -> Self {
        Queue {
            core,
            on_hold: Vec::with_capacity(128),
            in_flight: AHashSet::with_capacity(128),
            next_wake_up: Instant::now(),
            rx,
        }
    }

    pub async fn start(&mut self) {
        let mut is_paused = false;

        loop {
            let (on_hold, refresh_queue) = match tokio::time::timeout(
                self.next_wake_up.duration_since(Instant::now()),
                self.rx.recv(),
            )
            .await
            {
                Ok(Some(QueueEvent::Refresh(queue_id))) => {
                    if let Some(queue_id) = queue_id {
                        self.in_flight.remove(&queue_id);
                    }

                    (None, true)
                }
                Ok(Some(QueueEvent::WorkerDone(queue_id))) => {
                    self.in_flight.remove(&queue_id);

                    (None, false)
                }
                Ok(Some(QueueEvent::OnHold(on_hold))) => {
                    self.in_flight.remove(&on_hold.message.queue_id);

                    (on_hold.into(), false)
                }
                Ok(Some(QueueEvent::Paused(paused))) => {
                    is_paused = paused;
                    (None, false)
                }
                Err(_) => (None, true),
                Ok(Some(QueueEvent::Stop)) | Ok(None) => {
                    break;
                }
            };

            if !is_paused {
                // Deliver any concurrency limited messages
                let server = self.core.build_server();
                while let Some(queue_event) = self.next_on_hold() {
                    if let Some(message) =
                        DeliveryAttempt::new(queue_event).try_deliver(server.clone())
                    {
                        self.on_hold(message);
                    } else {
                        self.in_flight.insert(queue_event.queue_id);
                    }
                }

                // Deliver scheduled messages
                if refresh_queue || self.next_wake_up <= Instant::now() {
                    let now = now();
                    let mut next_wake_up = QUEUE_REFRESH;
                    for queue_event in server.next_event().await {
                        match self.is_on_hold(queue_event.queue_id) {
                            None => {
                                if queue_event.due <= now {
                                    if !self.in_flight.contains(&queue_event.queue_id) {
                                        if let Some(message) = DeliveryAttempt::new(queue_event)
                                            .try_deliver(server.clone())
                                        {
                                            self.on_hold(message);
                                        } else {
                                            self.in_flight.insert(queue_event.queue_id);
                                        }
                                    }
                                } else {
                                    let due_in = queue_event.due - now;
                                    if due_in < next_wake_up {
                                        next_wake_up = due_in;
                                    }
                                }
                            }
                            Some(on_hold)
                                if on_hold.limiters.is_empty()
                                    && on_hold.next_due.map_or(false, |due| due < next_wake_up) =>
                            {
                                next_wake_up = on_hold.next_due.unwrap();
                            }
                            _ => (),
                        }
                    }
                    self.next_wake_up = Instant::now() + Duration::from_secs(next_wake_up);
                }
            } else {
                // Queue is paused
                self.next_wake_up = Instant::now() + Duration::from_secs(86400);
            }

            // Add message on hold
            if let Some(on_hold) = on_hold {
                self.on_hold(on_hold);
            }
        }
    }

    pub fn is_on_hold(&self, queue_id: QueueId) -> Option<&OnHold<QueuedMessage>> {
        self.on_hold.iter().find(|o| o.message.queue_id == queue_id)
    }

    pub fn on_hold(&mut self, message: OnHold<QueuedMessage>) {
        self.on_hold.push(OnHold {
            next_due: message.next_due,
            limiters: message.limiters,
            message: message.message,
        });
    }

    pub fn next_on_hold(&mut self) -> Option<QueuedMessage> {
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
    fn spawn(self, core: Arc<Inner>);
}
