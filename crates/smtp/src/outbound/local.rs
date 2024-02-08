/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use smtp_proto::Response;
use tokio::sync::{mpsc, oneshot};
use utils::ipc::{DeliveryEvent, DeliveryResult, IngestMessage};

use crate::queue::{
    Error, ErrorDetails, HostResponse, Message, Recipient, Status, RCPT_STATUS_CHANGED,
};

impl Message {
    pub async fn deliver_local(
        &self,
        recipients: impl Iterator<Item = &mut Recipient>,
        delivery_tx: &mpsc::Sender<DeliveryEvent>,
        span: &tracing::Span,
    ) -> Status<(), Error> {
        // Prepare recipients list
        let mut total_rcpt = 0;
        let mut total_completed = 0;
        let mut pending_recipients = Vec::new();
        let mut recipient_addresses = Vec::new();
        for rcpt in recipients {
            total_rcpt += 1;
            if matches!(
                &rcpt.status,
                Status::Completed(_) | Status::PermanentFailure(_)
            ) {
                total_completed += 1;
                continue;
            }
            recipient_addresses.push(rcpt.address_lcase.clone());
            pending_recipients.push(rcpt);
        }

        // Create oneshot channel
        let (result_tx, result_rx) = oneshot::channel();

        // Deliver message to JMAP server
        let delivery_result = match delivery_tx
            .send(DeliveryEvent::Ingest {
                message: IngestMessage {
                    sender_address: self.return_path_lcase.clone(),
                    recipients: recipient_addresses,
                    message_blob: self.blob_hash.clone(),
                    message_size: self.size,
                },
                result_tx,
            })
            .await
        {
            Ok(_) => {
                // Wait for result
                match result_rx.await {
                    Ok(delivery_result) => delivery_result,
                    Err(_) => {
                        tracing::warn!(
                            parent: span,
                            context = "deliver_local",
                            event = "error",
                            reason = "result channel closed",
                        );
                        return Status::local_error();
                    }
                }
            }
            Err(_) => {
                tracing::warn!(
                    parent: span,
                    context = "deliver_local",
                    event = "error",
                    reason = "tx channel closed",
                );
                return Status::local_error();
            }
        };

        // Process delivery results
        for (rcpt, result) in pending_recipients.into_iter().zip(delivery_result) {
            rcpt.flags |= RCPT_STATUS_CHANGED;
            match result {
                DeliveryResult::Success => {
                    tracing::info!(
                        parent: span,
                        context = "deliver_local",
                        event = "delivered",
                        rcpt = rcpt.address,
                    );

                    rcpt.status = Status::Completed(HostResponse {
                        hostname: "localhost".to_string(),
                        response: Response {
                            code: 250,
                            esc: [2, 1, 5],
                            message: "OK".to_string(),
                        },
                    });
                    total_completed += 1;
                }
                DeliveryResult::TemporaryFailure { reason } => {
                    tracing::info!(
                        parent: span,
                        context = "deliver_local",
                        event = "deferred",
                        rcpt = rcpt.address,
                        reason = reason.as_ref(),
                    );
                    rcpt.status = Status::TemporaryFailure(HostResponse {
                        hostname: ErrorDetails {
                            entity: "localhost".to_string(),
                            details: format!("RCPT TO:<{}>", rcpt.address),
                        },
                        response: Response {
                            code: 451,
                            esc: [4, 3, 0],
                            message: reason.into_owned(),
                        },
                    });
                }
                DeliveryResult::PermanentFailure { code, reason } => {
                    tracing::info!(
                        parent: span,
                        context = "deliver_local",
                        event = "rejected",
                        rcpt = rcpt.address,
                        reason = reason.as_ref(),
                    );
                    total_completed += 1;
                    rcpt.status = Status::PermanentFailure(HostResponse {
                        hostname: ErrorDetails {
                            entity: "localhost".to_string(),
                            details: format!("RCPT TO:<{}>", rcpt.address),
                        },
                        response: Response {
                            code: 550,
                            esc: code,
                            message: reason.into_owned(),
                        },
                    });
                }
            }
        }

        if total_completed == total_rcpt {
            Status::Completed(())
        } else {
            Status::Scheduled
        }
    }
}
