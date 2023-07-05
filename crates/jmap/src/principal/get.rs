/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use jmap_proto::{
    error::method::MethodError,
    method::get::{GetRequest, GetResponse, RequestArguments},
    object::Object,
    types::{collection::Collection, property::Property, state::State, value::Value},
};

use crate::JMAP;

impl JMAP {
    pub async fn principal_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> Result<GetResponse, MethodError> {
        let ids = request.unwrap_ids(self.config.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            Property::Id,
            Property::Type,
            Property::Name,
            Property::Description,
            Property::Email,
            //Property::Timezone,
            //Property::Capabilities,
        ]);
        let email_submission_ids = self
            .get_document_ids(u32::MAX, Collection::EmailSubmission)
            .await?
            .unwrap_or_default();
        let ids = if let Some(ids) = ids {
            ids
        } else {
            email_submission_ids
                .iter()
                .take(self.config.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: State::Initial.into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the principal name
            let name = if let Some(name) = self.get_account_name(id.document_id()).await? {
                name
            } else {
                response.not_found.push(id);
                continue;
            };

            // Obtain the principal
            let principal = if let Some(principal) = self
                .directory
                .principal(&name)
                .await
                .map_err(|_| MethodError::ServerPartialFail)?
            {
                principal
            } else {
                response.not_found.push(id);
                continue;
            };

            let mut result = Object::with_capacity(properties.len());
            for property in &properties {
                let value = match property {
                    Property::Id => Value::Id(id),
                    Property::Type => Value::Text(principal.typ.to_jmap().to_string()),
                    Property::Name => Value::Text(principal.name.clone()),
                    Property::Description => principal
                        .description
                        .clone()
                        .map(Value::Text)
                        .unwrap_or(Value::Null),
                    Property::Email => self
                        .directory
                        .emails_by_name(&name)
                        .await
                        .map_err(|_| MethodError::ServerPartialFail)?
                        .into_iter()
                        .next()
                        .map(|email| Value::Text(email))
                        .unwrap_or(Value::Null),
                    _ => Value::Null,
                };

                result.append(property.clone(), value);
            }
            response.list.push(result);
        }

        Ok(response)
    }
}
