/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use ahash::{AHashMap, AHashSet};
use common::{
    Inner,
    core::BuildServer,
    ipc::{QueueEvent, QueueEventStatus},
    listener::limiter::ConcurrencyLimiter,
};
use rand::seq::SliceRandom;
use store::write::now;
use tokio::sync::mpsc;

use super::{
    Message, QueueId, Status,
    spool::{QUEUE_REFRESH, SmtpSpool},
};

pub struct Queue {
    pub core: Arc<Inner>,
    pub on_hold: AHashMap<QueueId, OnHold>,
    pub next_wake_up: Instant,
    pub rx: mpsc::Receiver<QueueEvent>,
}

#[derive(Debug)]
pub enum OnHold {
    InFlight,
    ConcurrencyLimited {
        limiters: Vec<ConcurrencyLimiter>,
        next_due: Option<u64>,
    },
    Locked {
        until: u64,
    },
}

impl SpawnQueue for mpsc::Receiver<QueueEvent> {
    fn spawn(self, core: Arc<Inner>) {
        tokio::spawn(async move {
            Queue::new(core, self).start().await;
        });
    }
}

const CLEANUP_INTERVAL: Duration = Duration::from_secs(10 * 60);
const BACK_PRESSURE_WARN_INTERVAL: Duration = Duration::from_secs(60);

impl Queue {
    pub fn new(core: Arc<Inner>, rx: mpsc::Receiver<QueueEvent>) -> Self {
        Queue {
            core,
            on_hold: AHashMap::with_capacity(128),
            next_wake_up: Instant::now(),
            rx,
        }
    }

    pub async fn start(&mut self) {
        let mut is_paused = false;
        let mut next_cleanup = Instant::now() + CLEANUP_INTERVAL;
        let mut last_backpressure_warning = Instant::now() - BACK_PRESSURE_WARN_INTERVAL;
        let mut in_flight_count = 0;
        let mut has_back_pressure = false;

        loop {
            let refresh_queue = match tokio::time::timeout(
                self.next_wake_up.duration_since(Instant::now()),
                self.rx.recv(),
            )
            .await
            {
                Ok(Some(QueueEvent::WorkerDone { queue_id, status })) => {
                    in_flight_count -= 1;

                    match status {
                        QueueEventStatus::Completed => {
                            self.on_hold.remove(&queue_id);
                            !self.on_hold.is_empty() || has_back_pressure
                        }
                        QueueEventStatus::Locked { until } => {
                            let due_in = Instant::now() + Duration::from_secs(until - now());
                            if due_in < self.next_wake_up {
                                self.next_wake_up = due_in;
                            }

                            self.on_hold.insert(queue_id, OnHold::Locked { until });
                            self.on_hold.len() > 1 || has_back_pressure
                        }
                        QueueEventStatus::Deferred => {
                            self.on_hold.remove(&queue_id);
                            true
                        }
                    }
                }
                Ok(Some(QueueEvent::Refresh)) => true,
                Ok(Some(QueueEvent::Paused(paused))) => {
                    self.core
                        .data
                        .queue_status
                        .store(!paused, Ordering::Relaxed);
                    is_paused = paused;
                    false
                }
                Err(_) => true,
                Ok(Some(QueueEvent::Stop)) | Ok(None) => {
                    break;
                }
            };

            if !is_paused {
                // Deliver scheduled messages
                if refresh_queue || self.next_wake_up <= Instant::now() {
                    // If the number of in-flight messages is greater than the maximum allowed, skip the queue
                    let server = self.core.build_server();
                    let max_in_flight = server.core.smtp.queue.max_threads;
                    has_back_pressure = in_flight_count >= max_in_flight;
                    if has_back_pressure {
                        self.next_wake_up = Instant::now() + Duration::from_secs(QUEUE_REFRESH);

                        if last_backpressure_warning.elapsed() >= BACK_PRESSURE_WARN_INTERVAL {
                            let queue_events = server.next_event().await;
                            last_backpressure_warning = Instant::now();
                            trc::event!(
                                Queue(trc::QueueEvent::BackPressure),
                                Reason =
                                    "Queue outbound processing capacity for this node exceeded.",
                                Total = queue_events.len(),
                                Details = self
                                    .on_hold
                                    .values()
                                    .fold([0, 0, 0], |mut acc, v| {
                                        match v {
                                            OnHold::InFlight => acc[0] += 1,
                                            OnHold::ConcurrencyLimited { .. } => acc[1] += 1,
                                            OnHold::Locked { .. } => acc[2] += 1,
                                        }
                                        acc
                                    })
                                    .into_iter()
                                    .map(trc::Value::from)
                                    .collect::<Vec<_>>(),
                                Limit = max_in_flight,
                            );
                        }
                        continue;
                    }

                    // Process queue events
                    let now = now();
                    let mut next_wake_up = QUEUE_REFRESH;
                    let mut queue_events = server.next_event().await;

                    if queue_events.len() > 5 {
                        queue_events.shuffle(&mut rand::rng());
                    }

                    for queue_event in &queue_events {
                        if queue_event.due <= now {
                            // Enforce global concurrency limits
                            if in_flight_count >= max_in_flight {
                                has_back_pressure = true;
                                if last_backpressure_warning.elapsed()
                                    >= BACK_PRESSURE_WARN_INTERVAL
                                {
                                    last_backpressure_warning = Instant::now();
                                    trc::event!(
                                        Queue(trc::QueueEvent::BackPressure),
                                        Reason = "Queue outbound processing capacity for this node exceeded.",
                                        Total = queue_events.len(),
                                        Details = self
                                            .on_hold
                                            .values()
                                            .fold([0, 0, 0], |mut acc, v| {
                                                match v {
                                                    OnHold::InFlight => acc[0] += 1,
                                                    OnHold::ConcurrencyLimited { .. } => {
                                                        acc[1] += 1
                                                    }
                                                    OnHold::Locked { .. } => acc[2] += 1,
                                                }
                                                acc
                                            })
                                            .into_iter()
                                            .map(trc::Value::from)
                                            .collect::<Vec<_>>(),
                                        Limit = max_in_flight,
                                    );
                                }
                                break;
                            }

                            // Check if the message is still on hold
                            if let Some(on_hold) = self.on_hold.get(&queue_event.queue_id) {
                                match on_hold {
                                    OnHold::Locked { until } => {
                                        if *until > now {
                                            let due_in = *until - now;
                                            if due_in < next_wake_up {
                                                next_wake_up = due_in;
                                            }
                                            continue;
                                        }
                                    }
                                    OnHold::ConcurrencyLimited { limiters, next_due } => {
                                        if !(limiters.iter().any(|l| {
                                            l.concurrent.load(Ordering::Relaxed) < l.max_concurrent
                                        }) || next_due.is_some_and(|due| due <= now))
                                        {
                                            continue;
                                        }
                                    }
                                    OnHold::InFlight => continue,
                                }

                                self.on_hold.remove(&queue_event.queue_id);
                            }

                            // Deliver message
                            in_flight_count += 1;
                            self.on_hold.insert(queue_event.queue_id, OnHold::InFlight);
                            queue_event.try_deliver(server.clone());
                        } else {
                            let due_in = queue_event.due - now;
                            if due_in < next_wake_up {
                                next_wake_up = due_in;
                            }
                        }
                    }

                    // Remove expired locks
                    let now = Instant::now();
                    if next_cleanup <= now {
                        next_cleanup = now + CLEANUP_INTERVAL;

                        if !self.on_hold.is_empty() {
                            let active_queue_ids = queue_events
                                .into_iter()
                                .map(|e| e.queue_id)
                                .collect::<AHashSet<_>>();
                            let now = store::write::now();
                            self.on_hold.retain(|queue_id, status| match status {
                                OnHold::InFlight => true,
                                OnHold::Locked { until } => *until > now,
                                OnHold::ConcurrencyLimited { .. } => {
                                    active_queue_ids.contains(queue_id)
                                }
                            });
                        }
                    }

                    self.next_wake_up = now + Duration::from_secs(next_wake_up);
                }
            } else {
                // Queue is paused
                self.next_wake_up = Instant::now() + Duration::from_secs(86400);
            }
        }
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

        if has_events { next_event.into() } else { None }
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
                    && next_event.as_ref().is_none_or(|ne| domain.retry.due.lt(ne))
                {
                    next_event = domain.retry.due.into();
                }
                if domain.notify.due > instant
                    && next_event
                        .as_ref()
                        .is_none_or(|ne| domain.notify.due.lt(ne))
                {
                    next_event = domain.notify.due.into();
                }
                if domain.expires > instant
                    && next_event.as_ref().is_none_or(|ne| domain.expires.lt(ne))
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
