use jmap_proto::types::{state::StateChange, type_state::TypeState};
use store::ahash::AHashMap;
use utils::ipc::{DeliveryResult, IngestMessage};

use crate::{mailbox::INBOX_ID, IngestError, JMAP};

impl JMAP {
    pub async fn deliver_message(&self, message: IngestMessage) -> Vec<DeliveryResult> {
        // Read message
        let raw_message = match message.read_message().await {
            Ok(raw_message) => raw_message,
            Err(_) => {
                return (0..message.recipients.len())
                    .map(|_| DeliveryResult::TemporaryFailure {
                        reason: "Temporary I/O error.".into(),
                    })
                    .collect::<Vec<_>>();
            }
        };

        // Obtain the UIDs for each recipient
        let mut recipients = Vec::with_capacity(message.recipients.len());
        let mut deliver_uids = AHashMap::with_capacity(message.recipients.len());
        for rcpt in &message.recipients {
            let uids = self.get_uids_by_address(rcpt).await;
            for uid in &uids {
                deliver_uids.insert(*uid, (DeliveryResult::Success, rcpt));
            }
            recipients.push(uids);
        }

        // Deliver to each recipient
        for (uid, (status, rcpt)) in &mut deliver_uids {
            // Check if there is an active sieve script
            let result = match self.sieve_script_get_active(*uid).await {
                Ok(Some(active_script)) => {
                    self.sieve_script_ingest(
                        &raw_message,
                        &message.sender_address,
                        rcpt,
                        *uid,
                        active_script,
                    )
                    .await
                }
                Ok(None) => {
                    self.email_ingest(
                        (&raw_message).into(),
                        *uid,
                        vec![INBOX_ID],
                        vec![],
                        None,
                        true,
                    )
                    .await
                }
                Err(_) => {
                    *status = DeliveryResult::TemporaryFailure {
                        reason: "Transient server failure.".into(),
                    };
                    continue;
                }
            };

            match result {
                Ok(ingested_message) => {
                    // Notify state change
                    if ingested_message.change_id != u64::MAX {
                        self.broadcast_state_change(
                            StateChange::new(*uid)
                                .with_change(TypeState::EmailDelivery, ingested_message.change_id)
                                .with_change(TypeState::Email, ingested_message.change_id)
                                .with_change(TypeState::Mailbox, ingested_message.change_id)
                                .with_change(TypeState::Thread, ingested_message.change_id),
                        )
                        .await;
                    }
                }
                Err(err) => match err {
                    IngestError::Temporary => {
                        *status = DeliveryResult::TemporaryFailure {
                            reason: "Transient server failure.".into(),
                        }
                    }
                    IngestError::Permanent { code, reason } => {
                        *status = DeliveryResult::PermanentFailure {
                            code,
                            reason: reason.into(),
                        }
                    }
                },
            }
        }

        // Build result
        recipients
            .into_iter()
            .map(|uids| {
                match uids.len() {
                    1 => {
                        // Delivery to single recipient
                        deliver_uids.get(&uids[0]).unwrap().0.clone()
                    }
                    0 => {
                        // Something went wrong
                        DeliveryResult::TemporaryFailure {
                            reason: "Address lookup failed.".into(),
                        }
                    }
                    _ => {
                        // Delivery to list, count number of successes and failures
                        let mut success = 0;
                        let mut temp_failures = 0;
                        for uid in uids {
                            match deliver_uids.get(&uid).unwrap().0 {
                                DeliveryResult::Success => success += 1,
                                DeliveryResult::TemporaryFailure { .. } => temp_failures += 1,
                                DeliveryResult::PermanentFailure { .. } => {}
                            }
                        }
                        if success > temp_failures {
                            DeliveryResult::Success
                        } else if temp_failures > 0 {
                            DeliveryResult::TemporaryFailure {
                                reason: "Delivery to one or more recipients failed temporarily."
                                    .into(),
                            }
                        } else {
                            DeliveryResult::PermanentFailure {
                                code: [5, 5, 0],
                                reason: "Delivery to all recipients failed.".into(),
                            }
                        }
                    }
                }
            })
            .collect()
    }
}
