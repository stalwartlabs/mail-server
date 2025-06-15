/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::object::Object;
use crate::object::FromLegacy;
use common::Server;
use email::identity::{EmailAddress, Identity};
use jmap_proto::types::{collection::Collection, property::Property, value::Value};
use store::{
    Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, ValueClass},
};
use trc::AddContext;

pub(crate) async fn migrate_identities(server: &Server, account_id: u32) -> trc::Result<u64> {
    // Obtain email ids
    let identity_ids = server
        .get_document_ids(account_id, Collection::Identity)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_identities = identity_ids.len();
    if num_identities == 0 {
        return Ok(0);
    }
    let mut did_migrate = false;

    for identity_id in &identity_ids {
        match server
            .store()
            .get_value::<Object<Value>>(ValueKey {
                account_id,
                collection: Collection::Identity.into(),
                document_id: identity_id,
                class: ValueClass::Property(Property::Value.into()),
            })
            .await
        {
            Ok(Some(legacy)) => {
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Identity)
                    .update_document(identity_id)
                    .set(
                        Property::Value,
                        Archiver::new(Identity::from_legacy(legacy))
                            .serialize()
                            .caused_by(trc::location!())?,
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
                        collection: Collection::Identity.into(),
                        document_id: identity_id,
                        class: ValueClass::Property(Property::Value.into()),
                    })
                    .await
                    .is_err()
                {
                    return Err(err
                        .account_id(account_id)
                        .document_id(identity_id)
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
                Collection::Identity,
                identity_ids
                    .max()
                    .map(|id| id as u64)
                    .unwrap_or(num_identities)
                    + 1,
            )
            .await
            .caused_by(trc::location!())?;
        Ok(num_identities)
    } else {
        Ok(0)
    }
}

impl FromLegacy for Identity {
    fn from_legacy(legacy: Object<Value>) -> Self {
        Identity {
            name: legacy
                .get(&Property::Name)
                .as_string()
                .unwrap_or_default()
                .to_string(),
            email: legacy
                .get(&Property::Email)
                .as_string()
                .unwrap_or_default()
                .to_string(),
            reply_to: convert_email_addresses(legacy.get(&Property::ReplyTo)),
            bcc: convert_email_addresses(legacy.get(&Property::Bcc)),
            text_signature: legacy
                .get(&Property::TextSignature)
                .as_string()
                .unwrap_or_default()
                .to_string(),
            html_signature: legacy
                .get(&Property::HtmlSignature)
                .as_string()
                .unwrap_or_default()
                .to_string(),
        }
    }
}

fn convert_email_addresses(value: &Value) -> Option<Vec<EmailAddress>> {
    if let Value::List(value) = value {
        let mut addrs = Vec::with_capacity(value.len());
        for addr in value {
            if let Value::Object(obj) = addr {
                let mut addr = EmailAddress {
                    name: None,
                    email: String::new(),
                };
                for (key, value) in &obj.0 {
                    match (key, value) {
                        (Property::Email, Value::Text(value)) => {
                            addr.email = value.to_string();
                        }
                        (Property::Name, Value::Text(value)) => {
                            addr.name = Some(value.to_string());
                        }
                        _ => {
                            break;
                        }
                    }
                }
                if !addr.email.is_empty() {
                    addrs.push(addr);
                }
            }
        }
        if !addrs.is_empty() { Some(addrs) } else { None }
    } else {
        None
    }
}
