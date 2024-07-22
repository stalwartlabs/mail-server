/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use ahash::AHashSet;
use parking_lot::Mutex;
use tokio::sync::mpsc::{self, error::TrySendError};

use crate::{channel::ChannelError, Event, EventType, Level};

const MAX_BATCH_SIZE: usize = 32768;

pub(crate) static SUBSCRIBER_UPDATE: Mutex<Vec<Subscriber>> = Mutex::new(Vec::new());

#[derive(Debug)]
pub(crate) struct Subscriber {
    pub level: Level,
    pub disabled: AHashSet<EventType>,
    pub tx: mpsc::Sender<Vec<Arc<Event>>>,
    pub lossy: bool,
    pub batch: Vec<Arc<Event>>,
}

pub struct SubscriberBuilder {
    pub level: Level,
    pub disabled: AHashSet<EventType>,
    pub lossy: bool,
}

impl Subscriber {
    #[inline(always)]
    pub fn push_event(&mut self, trace: Arc<Event>) {
        if trace.level >= self.level && !self.disabled.contains(&trace.inner) {
            self.batch.push(trace);
        }
    }

    pub fn send_batch(&mut self) -> Result<(), ChannelError> {
        if !self.batch.is_empty() {
            match self.tx.try_send(std::mem::take(&mut self.batch)) {
                Ok(_) => Ok(()),
                Err(TrySendError::Full(mut events)) => {
                    if self.lossy && events.len() > MAX_BATCH_SIZE {
                        events.retain(|e| e.level == Level::Error);
                        if events.len() > MAX_BATCH_SIZE {
                            events.truncate(MAX_BATCH_SIZE);
                        }
                    }
                    self.batch = events;
                    Ok(())
                }
                Err(TrySendError::Closed(_)) => Err(ChannelError),
            }
        } else {
            Ok(())
        }
    }
}

impl SubscriberBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    pub fn with_disabled(mut self, disabled: impl IntoIterator<Item = EventType>) -> Self {
        self.disabled.extend(disabled);
        self
    }

    pub fn with_lossy(mut self, lossy: bool) -> Self {
        self.lossy = lossy;
        self
    }

    pub fn register(self) -> mpsc::Receiver<Vec<Arc<Event>>> {
        let (tx, rx) = mpsc::channel(8192);

        SUBSCRIBER_UPDATE.lock().push(Subscriber {
            level: self.level,
            disabled: self.disabled,
            tx,
            lossy: self.lossy,
            batch: Vec::new(),
        });

        // Notify collector
        Event::new(EventType::Error(crate::Cause::Thread), Level::Info, 0).send();

        rx
    }
}

impl Default for SubscriberBuilder {
    fn default() -> Self {
        Self {
            level: Level::Info,
            disabled: AHashSet::new(),
            lossy: true,
        }
    }
}
