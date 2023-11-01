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

use jmap_proto::{
    error::method::MethodError,
    method::get::{GetRequest, GetResponse, RequestArguments},
    object::Object,
    types::{id::Id, property::Property, state::State, type_state::DataType, value::Value},
};

use crate::{auth::AccessToken, JMAP};

impl JMAP {
    pub async fn quota_get(
        &self,
        mut request: GetRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> Result<GetResponse, MethodError> {
        let ids = request.unwrap_ids(self.config.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            Property::Id,
            Property::ResourceType,
            Property::Used,
            Property::WarnLimit,
            Property::SoftLimit,
            Property::HardLimit,
            Property::Scope,
            Property::Name,
            Property::Description,
            Property::Types,
        ]);
        let account_id = request.account_id.document_id();
        let quota_ids = if access_token.quota > 0 {
            vec![0u32]
        } else {
            vec![]
        };
        let ids = if let Some(ids) = ids {
            ids
        } else {
            quota_ids.iter().map(|id| Id::from(*id)).collect()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: State::Initial.into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the sieve script object
            let document_id = id.document_id();
            if !quota_ids.contains(&document_id) {
                response.not_found.push(id.into());
                continue;
            }

            let mut result = Object::with_capacity(properties.len());
            for property in &properties {
                let value = match property {
                    Property::Id => Value::Id(id),
                    Property::ResourceType => "octets".to_string().into(),
                    Property::Used => (self.get_used_quota(account_id).await? as u64).into(),
                    Property::HardLimit => access_token.quota.into(),
                    Property::Scope => "account".to_string().into(),
                    Property::Name => access_token.name.clone().into(),
                    Property::Description => access_token.description.clone().into(),
                    Property::Types => vec![
                        Value::Text(DataType::Email.to_string()),
                        Value::Text(DataType::SieveScript.to_string()),
                    ]
                    .into(),

                    _ => Value::Null,
                };
                result.append(property.clone(), value);
            }
            response.list.push(result);
        }

        Ok(response)
    }
}
