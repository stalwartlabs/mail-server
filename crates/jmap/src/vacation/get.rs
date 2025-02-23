/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use email::sieve::SieveScript;
use jmap_proto::{
    method::get::{GetRequest, GetResponse, RequestArguments},
    request::reference::MaybeReference,
    types::{
        any_id::AnyId,
        collection::Collection,
        date::UTCDate,
        id::Id,
        property::Property,
        value::{Object, Value},
    },
};
use std::future::Future;
use store::query::Filter;

use crate::{JmapMethods, changes::state::StateManager};

pub trait VacationResponseGet: Sync + Send {
    fn vacation_response_get(
        &self,
        request: GetRequest<RequestArguments>,
    ) -> impl Future<Output = trc::Result<GetResponse>> + Send;

    fn get_vacation_sieve_script_id(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;
}

impl VacationResponseGet for Server {
    async fn vacation_response_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> trc::Result<GetResponse> {
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
                    .get_property::<SieveScript>(
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
                                result.append(Property::IsEnabled, obj.is_active);
                            }
                            Property::FromDate => {
                                result.append(
                                    Property::FromDate,
                                    obj.vacation_response.as_mut().and_then(|r| {
                                        r.from_date.take().map(UTCDate::from).map(Value::Date)
                                    }),
                                );
                            }
                            Property::ToDate => {
                                result.append(
                                    Property::ToDate,
                                    obj.vacation_response.as_mut().and_then(|r| {
                                        r.to_date.take().map(UTCDate::from).map(Value::Date)
                                    }),
                                );
                            }
                            Property::Subject => {
                                result.append(
                                    Property::Subject,
                                    obj.vacation_response
                                        .as_mut()
                                        .and_then(|r| r.subject.take().map(Value::from)),
                                );
                            }
                            Property::TextBody => {
                                result.append(
                                    Property::TextBody,
                                    obj.vacation_response
                                        .as_mut()
                                        .and_then(|r| r.text_body.take().map(Value::from)),
                                );
                            }
                            Property::HtmlBody => {
                                result.append(
                                    Property::HtmlBody,
                                    obj.vacation_response
                                        .as_mut()
                                        .and_then(|r| r.html_body.take().map(Value::from)),
                                );
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

    async fn get_vacation_sieve_script_id(&self, account_id: u32) -> trc::Result<Option<u32>> {
        self.filter(
            account_id,
            Collection::SieveScript,
            vec![Filter::eq(Property::Name, "vacation")],
        )
        .await
        .map(|r| r.results.min())
    }
}
