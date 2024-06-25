/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    error::method::MethodError,
    method::get::{GetRequest, GetResponse, RequestArguments},
    object::Object,
    request::reference::MaybeReference,
    types::{any_id::AnyId, collection::Collection, id::Id, property::Property, value::Value},
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
                match id.try_unwrap() {
                    Some(AnyId::Id(id)) if id.is_singleton() => {
                        do_get = true;
                    }
                    Some(id) => {
                        response.not_found.push(id);
                    }
                    _ => {}
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
                    response.not_found.push(Id::singleton().into());
                }
            } else {
                response.not_found.push(Id::singleton().into());
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
