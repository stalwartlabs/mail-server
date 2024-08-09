/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    cell::UnsafeCell,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use rtrb::{Consumer, Producer, PushError, RingBuffer};

use crate::{
    collector::{spawn_collector, CollectorThread, Update, COLLECTOR_UPDATES},
    Event, EventType,
};

pub(crate) static CHANNEL_FLAGS: AtomicU64 = AtomicU64::new(0);
pub(crate) const CHANNEL_SIZE: usize = 10240;
pub(crate) const CHANNEL_UPDATE_MARKER: u64 = 1 << 63;

thread_local! {
    static EVENT_TX: UnsafeCell<Sender> = {
        // Create channel.
        let (tx, rx) = RingBuffer::new(CHANNEL_SIZE);

        // Register receiver with collector.
        COLLECTOR_UPDATES.lock().push(Update::RegisterReceiver { receiver: Receiver { rx } });

        // Spawn collector thread.
        let collector = spawn_collector().clone();
        CHANNEL_FLAGS.fetch_or(CHANNEL_UPDATE_MARKER, Ordering::Relaxed);
        collector.thread().unpark();

        // Return sender.
        UnsafeCell::new(Sender {
            tx,
            collector,
            overflow: Vec::with_capacity(0),
        })
    };
}

pub struct Sender {
    tx: Producer<Event<EventType>>,
    collector: Arc<CollectorThread>,
    overflow: Vec<Event<EventType>>,
}

pub struct Receiver {
    rx: Consumer<Event<EventType>>,
}

#[derive(Debug)]
pub struct ChannelError;

impl Sender {
    pub fn send(&mut self, event: Event<EventType>) -> Result<(), ChannelError> {
        while let Some(event) = self.overflow.pop() {
            if let Err(PushError::Full(event)) = self.tx.push(event) {
                self.overflow.push(event);
                break;
            }
        }

        if let Err(PushError::Full(event)) = self.tx.push(event) {
            if self.overflow.len() <= CHANNEL_SIZE * 2 {
                self.overflow.push(event);
            } else {
                return Err(ChannelError);
            }
        }

        Ok(())
    }
}

impl Receiver {
    pub fn try_recv(&mut self) -> Result<Option<Event<EventType>>, ChannelError> {
        match self.rx.pop() {
            Ok(event) => Ok(Some(event)),
            Err(_) => {
                if !self.rx.is_abandoned() {
                    Ok(None)
                } else {
                    Err(ChannelError)
                }
            }
        }
    }
}

impl Event<EventType> {
    pub fn send(self) {
        // SAFETY: EVENT_TX is thread-local.
        let _ = EVENT_TX.try_with(|tx| unsafe {
            let tx = &mut *tx.get();
            if tx.send(self).is_ok() {
                CHANNEL_FLAGS.fetch_add(1, Ordering::Relaxed);
                tx.collector.thread().unpark();
            }
        });
    }
}
