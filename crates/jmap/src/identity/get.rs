/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use directory::QueryBy;
use jmap_proto::{
    error::method::MethodError,
    method::get::{GetRequest, GetResponse, RequestArguments},
    object::Object,
    types::{collection::Collection, property::Property, value::Value},
};
use store::{
    roaring::RoaringBitmap,
    write::{BatchBuilder, F_VALUE},
};

use crate::JMAP;

use super::set::sanitize_email;

impl JMAP {
    pub async fn identity_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> Result<GetResponse, MethodError> {
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
                .get_state(account_id, Collection::Identity)
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
            let mut identity = if let Some(identity) = self
                .get_property::<Object<Value>>(
                    account_id,
                    Collection::Identity,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                identity
            } else {
                response.not_found.push(id.into());
                continue;
            };
            let mut result = Object::with_capacity(properties.len());
            for property in &properties {
                match property {
                    Property::Id => {
                        result.append(Property::Id, Value::Id(id));
                    }
                    Property::MayDelete => {
                        result.append(Property::MayDelete, Value::Bool(true));
                    }
                    Property::TextSignature | Property::HtmlSignature => {
                        result.append(
                            property.clone(),
                            identity
                                .properties
                                .remove(property)
                                .unwrap_or(Value::Text(String::new())),
                        );
                    }
                    property => {
                        result.append(property.clone(), identity.remove(property));
                    }
                }
            }
            response.list.push(result);
        }

        Ok(response)
    }

    pub async fn identity_get_or_create(
        &self,
        account_id: u32,
    ) -> Result<RoaringBitmap, MethodError> {
        let mut identity_ids = self
            .get_document_ids(account_id, Collection::Identity)
            .await?
            .unwrap_or_default();
        if !identity_ids.is_empty() {
            return Ok(identity_ids);
        }

        // Obtain principal
        let principal = self
            .core
            .storage
            .directory
            .query(QueryBy::Id(account_id), false)
            .await
            .map_err(|err| {
                tracing::error!(
                    event = "error",
                    context = "identity_get_or_create",
                    error = ?err,
                    "Failed to query directory.");
                MethodError::ServerPartialFail
            })?
            .unwrap_or_default();
        if principal.emails.is_empty() {
            return Ok(identity_ids);
        }

        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Identity);

        // Create identities
        let name = principal
            .description
            .unwrap_or(principal.name)
            .trim()
            .to_string();
        let has_many = principal.emails.len() > 1;
        for (idx, email) in principal.emails.into_iter().enumerate() {
            let document_id = idx as u32;
            let email = sanitize_email(&email).unwrap_or_default();
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
            batch.create_document_with_id(document_id).value(
                Property::Value,
                Object::with_capacity(4)
                    .with_property(Property::Name, name)
                    .with_property(Property::Email, email),
                F_VALUE,
            );
            identity_ids.insert(document_id);
        }
        self.core
            .storage
            .data
            .write(batch.build())
            .await
            .map_err(|err| {
                tracing::error!(
                event = "error",
                context = "identity_get_or_create",
                error = ?err,
                "Failed to create identities.");
                MethodError::ServerPartialFail
            })?;

        Ok(identity_ids)
    }
}
