/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use futures::StreamExt;

use crate::dispatch::pubsub::{Msg, PubSubStream};

use super::NatsStore;

pub struct NatsPubSubStream {
    subs: async_nats::Subscriber,
}

impl NatsStore {
    pub async fn publish(&self, topic: &'static str, message: Vec<u8>) -> trc::Result<()> {
        self.client
            .publish(topic, message.into())
            .await
            .map_err(into_error)
    }

    pub async fn subscribe(&self, topic: &'static str) -> trc::Result<PubSubStream> {
        self.client
            .subscribe(topic)
            .await
            .map_err(into_error)
            .map(|subs| PubSubStream::Nats(NatsPubSubStream { subs }))
    }
}

impl NatsPubSubStream {
    pub async fn next(&mut self) -> Option<Msg> {
        self.subs.next().await.map(Msg::Nats)
    }
}

#[inline(always)]
fn into_error(err: impl Display) -> trc::Error {
    trc::StoreEvent::NatsError.reason(err)
}
