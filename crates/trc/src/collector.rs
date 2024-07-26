/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
    thread::{park, Builder, JoinHandle},
};

use ahash::AHashMap;
use arc_swap::ArcSwap;

use crate::{
    channel::{EVENT_COUNT, EVENT_RXS},
    subscriber::{Subscriber, SUBSCRIBER_UPDATE},
    Event, EventType, Level, ServerEvent,
};

pub(crate) static TRACING_LEVEL: AtomicUsize = AtomicUsize::new(Level::Info as usize);

pub(crate) type CollectorThread = JoinHandle<()>;

#[derive(Default)]
pub struct Collector {
    subscribers: Vec<Subscriber>,
}

impl Collector {
    fn collect(&mut self) -> bool {
        if EVENT_COUNT.swap(0, Ordering::Relaxed) == 0 {
            park();
        }

        // Collect all events
        let mut do_continue = true;
        EVENT_RXS.lock().retain_mut(|rx| {
            while do_continue {
                match rx.try_recv() {
                    Ok(Some(event)) => {
                        if !event.keys.is_empty() {
                            // Process events
                            for subscriber in self.subscribers.iter_mut() {
                                subscriber.push_event(event.clone());
                            }
                        } else {
                            // Register subscriber
                            let subscribers = { std::mem::take(&mut (*SUBSCRIBER_UPDATE.lock())) };
                            if !subscribers.is_empty() {
                                self.subscribers.extend(subscribers);
                            } else if event.matches(EventType::Server(ServerEvent::Shutdown)) {
                                do_continue = false;
                                return false;
                            }
                        }
                    }
                    Ok(None) => {
                        return true;
                    }
                    Err(_) => {
                        return false; // Channel is closed, remove.
                    }
                }
            }

            false
        });

        if !self.subscribers.is_empty() {
            if do_continue {
                // Send batched events
                self.subscribers
                    .retain_mut(|subscriber| subscriber.send_batch().is_ok());
            } else {
                // Send remaining events
                for mut subscriber in self.subscribers.drain(..) {
                    let _ = subscriber.send_batch();
                }
            }
        }

        do_continue
    }

    pub fn set_level(level: Level) {
        TRACING_LEVEL.store(level as usize, Ordering::Relaxed);
    }

    pub fn update_custom_levels(levels: AHashMap<EventType, Level>) {
        custom_levels().store(Arc::new(levels));
    }

    pub fn shutdown() {
        Event::new(EventType::Server(ServerEvent::Shutdown)).send()
    }
}

pub(crate) fn spawn_collector() -> &'static Arc<CollectorThread> {
    static COLLECTOR: OnceLock<Arc<CollectorThread>> = OnceLock::new();
    COLLECTOR.get_or_init(|| {
        Arc::new(
            Builder::new()
                .name("stalwart-collector".to_string())
                .spawn(move || {
                    let mut collector = Collector::default();

                    while collector.collect() {}
                })
                .expect("Failed to start event collector"),
        )
    })
}

fn custom_levels() -> &'static ArcSwap<AHashMap<EventType, Level>> {
    static CUSTOM_LEVELS: OnceLock<ArcSwap<AHashMap<EventType, Level>>> = OnceLock::new();
    CUSTOM_LEVELS.get_or_init(|| ArcSwap::from_pointee(Default::default()))
}

impl EventType {
    #[inline(always)]
    pub fn effective_level(&self) -> Level {
        custom_levels()
            .load()
            .get(self)
            .copied()
            .unwrap_or_else(|| self.level())
    }
}

impl Level {
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self as usize >= TRACING_LEVEL.load(Ordering::Relaxed)
    }
}
