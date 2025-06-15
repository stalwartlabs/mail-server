/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, storage::index::ObjectIndexBuilder};
use directory::QueryBy;
use email::identity::{ArchivedEmailAddress, Identity};
use jmap_proto::{
    method::get::{GetRequest, GetResponse, RequestArguments},
    types::{
        collection::{Collection, SyncCollection},
        property::Property,
        value::{Object, Value},
    },
};
use store::{
    rkyv::{option::ArchivedOption, vec::ArchivedVec},
    roaring::RoaringBitmap,
    write::BatchBuilder,
};
use trc::AddContext;
use utils::sanitize_email;

use crate::changes::state::StateManager;

use std::future::Future;

pub trait IdentityGet: Sync + Send {
    fn identity_get(
        &self,
        request: GetRequest<RequestArguments>,
    ) -> impl Future<Output = trc::Result<GetResponse>> + Send;

    fn identity_get_or_create(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;
}

impl IdentityGet for Server {
    async fn identity_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> trc::Result<GetResponse> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            Property::Id,
            Property::Name,
            Property::Email,
            Property::ReplyTo,
            Property::Bcc,
            Property::TextSignature,
            Property::HtmlSignature,
            Property::MayDelete,
        ]);
        let account_id = request.account_id.document_id();
        let identity_ids = self.identity_get_or_create(account_id).await?;
        let ids = if let Some(ids) = ids {
            ids
        } else {
            identity_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self
                .get_state(account_id, SyncCollection::Identity)
                .await?
                .into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the identity object
            let document_id = id.document_id();
            if !identity_ids.contains(document_id) {
                response.not_found.push(id.into());
                continue;
            }
            let _identity = if let Some(identity) = self
                .get_archive(account_id, Collection::Identity, document_id)
                .await?
            {
                identity
            } else {
                response.not_found.push(id.into());
                continue;
            };
            let identity = _identity
                .unarchive::<Identity>()
                .caused_by(trc::location!())?;
            let mut result = Object::with_capacity(properties.len());
            for property in &properties {
                match property {
                    Property::Id => {
                        result.append(Property::Id, Value::Id(id));
                    }
                    Property::MayDelete => {
                        result.append(Property::MayDelete, Value::Bool(true));
                    }
                    Property::Name => {
                        result.append(Property::Name, identity.name.to_string());
                    }
                    Property::Email => {
                        result.append(Property::Email, identity.email.to_string());
                    }
                    Property::TextSignature => {
                        result.append(Property::TextSignature, identity.text_signature.to_string());
                    }
                    Property::HtmlSignature => {
                        result.append(Property::HtmlSignature, identity.html_signature.to_string());
                    }
                    Property::Bcc => {
                        result.append(Property::Bcc, email_to_value(&identity.bcc));
                    }
                    Property::ReplyTo => {
                        result.append(Property::ReplyTo, email_to_value(&identity.reply_to));
                    }
                    property => {
                        result.append(property.clone(), Value::Null);
                    }
                }
            }
            response.list.push(result);
        }

        Ok(response)
    }

    async fn identity_get_or_create(&self, account_id: u32) -> trc::Result<RoaringBitmap> {
        let mut identity_ids = self
            .get_document_ids(account_id, Collection::Identity)
            .await?
            .unwrap_or_default();
        if !identity_ids.is_empty() {
            return Ok(identity_ids);
        }

        // Obtain principal
        let principal = if let Some(principal) = self
            .core
            .storage
            .directory
            .query(QueryBy::Id(account_id), false)
            .await
            .caused_by(trc::location!())?
        {
            principal
        } else {
            return Ok(identity_ids);
        };
        let num_emails = principal.emails.len();
        if num_emails == 0 {
            return Ok(identity_ids);
        }

        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Identity);

        // Create identities
        let name = principal.description.unwrap_or(principal.name);
        let has_many = num_emails > 1;
        let mut next_document_id = self
            .store()
            .assign_document_ids(account_id, Collection::Identity, num_emails as u64)
            .await
            .caused_by(trc::location!())?;
        for email in &principal.emails {
            let email = sanitize_email(email).unwrap_or_default();
            if email.is_empty() {
                continue;
            }
            let name = if name.is_empty() {
                email.clone()
            } else if has_many {
                format!("{} <{}>", name, email)
            } else {
                name.clone()
            };
            let document_id = next_document_id;
            next_document_id -= 1;
            batch
                .create_document(document_id)
                .custom(ObjectIndexBuilder::<(), _>::new().with_changes(Identity {
                    name,
                    email,
                    ..Default::default()
                }))
                .caused_by(trc::location!())?;
            identity_ids.insert(document_id);
        }
        self.commit_batch(batch).await.caused_by(trc::location!())?;

        Ok(identity_ids)
    }
}

fn email_to_value(email: &ArchivedOption<ArchivedVec<ArchivedEmailAddress>>) -> Value {
    if let ArchivedOption::Some(email) = email {
        Value::List(
            email
                .iter()
                .map(|email| {
                    Value::Object(
                        Object::with_capacity(2)
                            .with_property(Property::Name, &email.name)
                            .with_property(Property::Email, &email.email),
                    )
                })
                .collect(),
        )
    } else {
        Value::Null
    }
}
