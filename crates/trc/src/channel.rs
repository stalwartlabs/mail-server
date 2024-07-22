/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    cell::UnsafeCell,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use parking_lot::Mutex;
use rtrb::{Consumer, Producer, PushError, RingBuffer};

use crate::{
    collector::{spawn_collector, CollectorThread},
    Event,
};

pub(crate) static EVENT_RXS: Mutex<Vec<Receiver>> = Mutex::new(Vec::new());
pub(crate) static EVENT_COUNT: AtomicUsize = AtomicUsize::new(0);
pub(crate) const CHANNEL_SIZE: usize = 10240;

thread_local! {
    static EVENT_TX: UnsafeCell<Sender> = {
        let (tx, rx) = RingBuffer::new(CHANNEL_SIZE);
        EVENT_RXS.lock().push(Receiver { rx });
        UnsafeCell::new(Sender {
            tx,
            collector: spawn_collector().clone(),
            overflow: Vec::with_capacity(0),
        })
    };
}

pub struct Sender {
    tx: Producer<Arc<Event>>,
    collector: Arc<CollectorThread>,
    overflow: Vec<Arc<Event>>,
}

pub struct Receiver {
    rx: Consumer<Arc<Event>>,
}

#[derive(Debug)]
pub struct ChannelError;

impl Sender {
    pub fn send(&mut self, event: Arc<Event>) -> Result<(), ChannelError> {
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
    pub fn try_recv(&mut self) -> Result<Option<Arc<Event>>, ChannelError> {
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

impl Event {
    pub fn send(self) {
        // SAFETY: EVENT_TX is thread-local.
        let _ = EVENT_TX.try_with(|tx| unsafe {
            let tx = &mut *tx.get();
            if tx.send(Arc::new(self)).is_ok() {
                EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
                tx.collector.thread().unpark();
            }
        });
    }
}
