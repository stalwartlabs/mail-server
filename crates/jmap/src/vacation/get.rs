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
    request::reference::MaybeReference,
    types::{collection::Collection, id::Id, property::Property, value::Value},
};
use store::query::Filter;

use crate::JMAP;

impl JMAP {
    pub async fn vacation_response_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> Result<GetResponse, MethodError> {
        let account_id = request.account_id.document_id();
        let properties = request.unwrap_properties(&[
            Property::Id,
            Property::IsEnabled,
            Property::FromDate,
            Property::ToDate,
            Property::Subject,
            Property::TextBody,
            Property::HtmlBody,
        ]);
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self
                .get_state(account_id, Collection::SieveScript)
                .await?
                .into(),
            list: Vec::with_capacity(1),
            not_found: vec![],
        };

        let do_get = if let Some(MaybeReference::Value(ids)) = request.ids {
            let mut do_get = false;
            for id in ids {
                if id.is_singleton() {
                    do_get = true;
                } else {
                    response.not_found.push(id);
                }
            }
            do_get
        } else {
            true
        };
        if do_get {
            if let Some(document_id) = self.get_vacation_sieve_script_id(account_id).await? {
                if let Some(mut obj) = self
                    .get_property::<Object<Value>>(
                        account_id,
                        Collection::SieveScript,
                        document_id,
                        Property::Value,
                    )
                    .await?
                {
                    let mut result = Object::with_capacity(properties.len());
                    for property in &properties {
                        match property {
                            Property::Id => {
                                result.append(Property::Id, Value::Id(Id::singleton()));
                            }
                            Property::IsEnabled => {
                                result.append(Property::IsEnabled, obj.remove(&Property::IsActive));
                            }
                            Property::FromDate
                            | Property::ToDate
                            | Property::Subject
                            | Property::TextBody
                            | Property::HtmlBody => {
                                result.append(property.clone(), obj.remove(property));
                            }
                            property => {
                                result.append(property.clone(), Value::Null);
                            }
                        }
                    }
                    response.list.push(result);
                } else {
                    response.not_found.push(Id::singleton());
                }
            } else {
                response.not_found.push(Id::singleton());
            }
        }

        Ok(response)
    }

    pub async fn get_vacation_sieve_script_id(
        &self,
        account_id: u32,
    ) -> Result<Option<u32>, MethodError> {
        self.filter(
            account_id,
            Collection::SieveScript,
            vec![Filter::eq(Property::Name, "vacation")],
        )
        .await
        .map(|r| r.results.min())
    }
}
