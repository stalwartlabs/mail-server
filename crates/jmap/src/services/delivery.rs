/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{core::BuildServer, ipc::DeliveryEvent, Inner};
use tokio::sync::{mpsc, Semaphore};

use super::ingest::MailDelivery;

pub fn spawn_delivery_manager(inner: Arc<Inner>, mut delivery_rx: mpsc::Receiver<DeliveryEvent>) {
    tokio::spawn(async move {
        let semaphore = Arc::new(Semaphore::new(
            inner
                .shared_core
                .load()
                .smtp
                .queue
                .throttle
                .local_concurrency,
        ));

        loop {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    trc::error!(trc::StoreEvent::UnexpectedError
                        .into_err()
                        .details("Semaphore error")
                        .caused_by(trc::location!()));
                    break;
                }
            };

            match delivery_rx.recv().await {
                Some(event) => match event {
                    DeliveryEvent::Ingest { message, result_tx } => {
                        let server = inner.build_server();

                        tokio::spawn(async move {
                            result_tx.send(server.deliver_message(message).await).ok();

                            drop(permit);
                        });
                    }
                    DeliveryEvent::Stop => break,
                },
                None => {
                    break;
                }
            }
        }
    });
}
