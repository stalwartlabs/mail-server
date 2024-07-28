/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{DeliveryEvent, DeliveryResult, IngestMessage};
use smtp_proto::Response;
use tokio::sync::{mpsc, oneshot};
use trc::ServerEvent;

use crate::queue::{
    Error, ErrorDetails, HostResponse, Message, Recipient, Status, RCPT_STATUS_CHANGED,
};

impl Message {
    pub async fn deliver_local(
        &self,
        recipients: impl Iterator<Item = &mut Recipient>,
        delivery_tx: &mpsc::Sender<DeliveryEvent>,
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
                    session_id: self.id,
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
                        trc::event!(
                            Server(ServerEvent::ThreadError),
                            CausedBy = trc::location!(),
                            SpanId = self.id,
                            Reason = "Result channel closed",
                        );
                        return Status::local_error();
                    }
                }
            }
            Err(_) => {
                trc::event!(
                    Server(ServerEvent::ThreadError),
                    CausedBy = trc::location!(),
                    SpanId = self.id,
                    Reason = "TX channel closed",
                );
                return Status::local_error();
            }
        };

        // Process delivery results
        for (rcpt, result) in pending_recipients.into_iter().zip(delivery_result) {
            rcpt.flags |= RCPT_STATUS_CHANGED;
            match result {
                DeliveryResult::Success => {
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
