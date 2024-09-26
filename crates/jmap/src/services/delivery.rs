/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{core::BuildServer, ipc::DeliveryEvent, Inner};
use tokio::sync::mpsc;

use super::ingest::MailDelivery;

pub fn spawn_delivery_manager(inner: Arc<Inner>, mut delivery_rx: mpsc::Receiver<DeliveryEvent>) {
    tokio::spawn(async move {
        while let Some(event) = delivery_rx.recv().await {
            match event {
                DeliveryEvent::Ingest { message, result_tx } => {
                    result_tx
                        .send(inner.build_server().deliver_message(message).await)
                        .ok();
                }
                DeliveryEvent::Stop => break,
            }
        }
    });
}
