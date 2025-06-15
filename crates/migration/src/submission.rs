/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::object::Object;
use crate::object::FromLegacy;
use common::Server;
use email::submission::{
    Address, Delivered, DeliveryStatus, EmailSubmission, Envelope, UndoStatus,
};
use jmap_proto::types::{collection::Collection, property::Property, value::Value};
use store::{
    SUBSPACE_BITMAP_TAG, SUBSPACE_BITMAP_TEXT, SUBSPACE_INDEXES, Serialize, SerializeInfallible,
    U64_LEN, ValueKey,
    write::{
        AlignedBytes, AnyKey, Archive, Archiver, BatchBuilder, ValueClass, key::KeySerializer,
    },
};
use trc::AddContext;
use utils::map::vec_map::VecMap;

pub(crate) async fn migrate_email_submissions(
    server: &Server,
    account_id: u32,
) -> trc::Result<u64> {
    // Obtain email ids
    let email_submission_ids = server
        .get_document_ids(account_id, Collection::EmailSubmission)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_email_submissions = email_submission_ids.len();
    if num_email_submissions == 0 {
        return Ok(0);
    }
    let mut did_migrate = false;

    // Delete indexes
    for subspace in [SUBSPACE_INDEXES, SUBSPACE_BITMAP_TAG, SUBSPACE_BITMAP_TEXT] {
        server
            .store()
            .delete_range(
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::EmailSubmission))
                        .finalize(),
                },
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::EmailSubmission))
                        .write(&[u8::MAX; 16][..])
                        .finalize(),
                },
            )
            .await
            .caused_by(trc::location!())?;
    }

    for email_submission_id in &email_submission_ids {
        match server
            .store()
            .get_value::<Object<Value>>(ValueKey {
                account_id,
                collection: Collection::EmailSubmission.into(),
                document_id: email_submission_id,
                class: ValueClass::Property(Property::Value.into()),
            })
            .await
        {
            Ok(Some(legacy)) => {
                let es = EmailSubmission::from_legacy(legacy);
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::EmailSubmission)
                    .update_document(email_submission_id)
                    .index(Property::UndoStatus, es.undo_status.as_index())
                    .index(Property::EmailId, es.email_id.serialize())
                    .index(Property::ThreadId, es.thread_id.serialize())
                    .index(Property::IdentityId, es.identity_id.serialize())
                    .index(Property::SendAt, es.send_at.serialize())
                    .set(
                        Property::Value,
                        Archiver::new(es).serialize().caused_by(trc::location!())?,
                    );
                did_migrate = true;

                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
            Ok(None) => (),
            Err(err) => {
                if server
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey {
                        account_id,
                        collection: Collection::EmailSubmission.into(),
                        document_id: email_submission_id,
                        class: ValueClass::Property(Property::Value.into()),
                    })
                    .await
                    .is_err()
                {
                    return Err(err
                        .account_id(account_id)
                        .document_id(email_submission_id)
                        .caused_by(trc::location!()));
                }
            }
        }
    }

    // Increment document id counter
    if did_migrate {
        server
            .store()
            .assign_document_ids(
                account_id,
                Collection::EmailSubmission,
                email_submission_ids
                    .max()
                    .map(|id| id as u64)
                    .unwrap_or(num_email_submissions)
                    + 1,
            )
            .await
            .caused_by(trc::location!())?;
        Ok(num_email_submissions)
    } else {
        Ok(0)
    }
}

impl FromLegacy for EmailSubmission {
    fn from_legacy(legacy: Object<Value>) -> Self {
        EmailSubmission {
            email_id: legacy.get(&Property::EmailId).as_uint().unwrap_or_default() as u32,
            thread_id: legacy
                .get(&Property::ThreadId)
                .as_uint()
                .unwrap_or_default() as u32,
            identity_id: legacy
                .get(&Property::IdentityId)
                .as_uint()
                .unwrap_or_default() as u32,
            send_at: legacy
                .get(&Property::SentAt)
                .as_date()
                .map(|s| s.timestamp() as u64)
                .unwrap_or_default(),
            queue_id: legacy.get(&Property::MessageId).as_uint(),
            undo_status: legacy
                .get(&Property::UndoStatus)
                .as_string()
                .and_then(UndoStatus::parse)
                .unwrap_or(UndoStatus::Final),
            envelope: convert_envelope(legacy.get(&Property::Envelope)),
            delivery_status: convert_delivery_status(legacy.get(&Property::DeliveryStatus)),
        }
    }
}

fn convert_delivery_status(value: &Value) -> VecMap<String, DeliveryStatus> {
    let mut status = VecMap::new();
    if let Value::List(list) = value {
        for value in list {
            if let Value::Object(obj) = value {
                for (k, v) in obj.0.iter() {
                    if let (Property::_T(k), Value::Object(v)) = (k, v) {
                        let mut delivery_status = DeliveryStatus {
                            smtp_reply: String::new(),
                            delivered: Delivered::Unknown,
                            displayed: false,
                        };

                        for (property, value) in &v.0 {
                            match (property, value) {
                                (Property::Delivered, Value::Text(v)) => match v.as_str() {
                                    "queued" => delivery_status.delivered = Delivered::Queued,
                                    "yes" => delivery_status.delivered = Delivered::Yes,
                                    "unknown" => delivery_status.delivered = Delivered::Unknown,
                                    "no" => delivery_status.delivered = Delivered::No,
                                    _ => {}
                                },
                                (Property::SmtpReply, Value::Text(v)) => {
                                    delivery_status.smtp_reply = v.to_string();
                                }

                                _ => {}
                            }
                        }

                        status.append(k.to_string(), delivery_status);
                    }
                }
            }
        }
    }
    status
}

fn convert_envelope(value: &Value) -> Envelope {
    let mut envelope = Envelope {
        mail_from: Default::default(),
        rcpt_to: vec![],
    };

    if let Value::Object(obj) = value {
        for (property, value) in &obj.0 {
            match (property, value) {
                (Property::MailFrom, _) => {
                    envelope.mail_from = convert_envelope_address(value).unwrap_or_default();
                }
                (Property::RcptTo, Value::List(value)) => {
                    for addr in value {
                        if let Some(addr) = convert_envelope_address(addr) {
                            envelope.rcpt_to.push(addr);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    envelope
}

fn convert_envelope_address(envelope: &Value) -> Option<Address> {
    if let Value::Object(envelope) = envelope {
        if let (Value::Text(email), Value::Object(params)) = (
            envelope.get(&Property::Email),
            envelope.get(&Property::Parameters),
        ) {
            let mut addr = Address {
                email: email.to_string(),
                parameters: None,
            };
            for (k, v) in params.0.iter() {
                if let Property::_T(k) = &k {
                    if !k.is_empty() {
                        let k = k.to_string();
                        let v = v.as_string().map(|s| s.to_string());

                        addr.parameters.get_or_insert_default().append(k, v);
                    }
                }
            }
            return Some(addr);
        }
    }

    None
}
