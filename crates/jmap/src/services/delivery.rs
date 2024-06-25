/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::DeliveryEvent;
use tokio::sync::mpsc;

use crate::{JmapInstance, JMAP};

pub fn spawn_delivery_manager(core: JmapInstance, mut delivery_rx: mpsc::Receiver<DeliveryEvent>) {
    tokio::spawn(async move {
        while let Some(event) = delivery_rx.recv().await {
            match event {
                DeliveryEvent::Ingest { message, result_tx } => {
                    result_tx
                        .send(JMAP::from(core.clone()).deliver_message(message).await)
                        .ok();
                }
                DeliveryEvent::Stop => break,
            }
        }
    });
}
