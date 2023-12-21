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
        let ids = request.unwrap_ids(self.config.get_max_objects)?;
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
                .take(self.config.get_max_objects)
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
            let mut push = if let Some(push) = self
                .get_property::<Object<Value>>(
                    account_id,
                    Collection::Identity,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                push
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
                    property => {
                        result.append(property.clone(), push.remove(property));
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
        for email in principal.emails {
            let email = sanitize_email(&email).unwrap_or_default();
            if email.is_empty() {
                continue;
            }
            let identity_id = self
                .assign_document_id(account_id, Collection::Identity)
                .await?;
            let name = if name.is_empty() {
                email.clone()
            } else if has_many {
                format!("{} <{}>", name, email)
            } else {
                name.clone()
            };
            batch.create_document(identity_id).value(
                Property::Value,
                Object::with_capacity(4)
                    .with_property(Property::Name, name)
                    .with_property(Property::Email, email),
                F_VALUE,
            );
            identity_ids.insert(identity_id);
        }
        self.store.write(batch.build()).await.map_err(|err| {
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
