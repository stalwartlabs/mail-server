/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    error::method::MethodError,
    object::{blob, email, Object},
    parser::{json::Parser, Error, JsonObjectParser, Token},
    request::{
        method::MethodObject,
        reference::{MaybeReference, ResultReference},
        RequestProperty, RequestPropertyParser,
    },
    types::{any_id::AnyId, blob::BlobId, id::Id, property::Property, state::State, value::Value},
};

#[derive(Debug, Clone)]
pub struct GetRequest<T> {
    pub account_id: Id,
    pub ids: Option<MaybeReference<Vec<MaybeReference<AnyId, String>>, ResultReference>>,
    pub properties: Option<MaybeReference<Vec<Property>, ResultReference>>,
    pub arguments: T,
}

#[derive(Debug, Clone)]
pub enum RequestArguments {
    Email(email::GetArguments),
    Mailbox,
    Thread,
    Identity,
    EmailSubmission,
    PushSubscription,
    SieveScript,
    VacationResponse,
    Principal,
    Quota,
    Blob(blob::GetArguments),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GetResponse {
    #[serde(rename = "accountId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<Id>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,

    pub list: Vec<Object<Value>>,

    #[serde(rename = "notFound")]
    pub not_found: Vec<AnyId>,
}

impl JsonObjectParser for GetRequest<RequestArguments> {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut request = GetRequest {
            arguments: match &parser.ctx {
                MethodObject::Email => RequestArguments::Email(Default::default()),
                MethodObject::Mailbox => RequestArguments::Mailbox,
                MethodObject::Thread => RequestArguments::Thread,
                MethodObject::Identity => RequestArguments::Identity,
                MethodObject::EmailSubmission => RequestArguments::EmailSubmission,
                MethodObject::PushSubscription => RequestArguments::PushSubscription,
                MethodObject::SieveScript => RequestArguments::SieveScript,
                MethodObject::VacationResponse => RequestArguments::VacationResponse,
                MethodObject::Principal => RequestArguments::Principal,
                MethodObject::Blob => RequestArguments::Blob(Default::default()),
                MethodObject::Quota => RequestArguments::Quota,
                _ => {
                    return Err(Error::Method(MethodError::UnknownMethod(format!(
                        "{}/get",
                        parser.ctx
                    ))))
                }
            },
            account_id: Id::default(),
            ids: None,
            properties: None,
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x0064_4974_6e75_6f63_6361 if !key.is_ref => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x0073_6469 => {
                    request.ids = if !key.is_ref {
                        if parser.ctx != MethodObject::Blob {
                            <Option<Vec<MaybeReference<Id, String>>>>::parse(parser)?.map(|ids| {
                                MaybeReference::Value(ids.into_iter().map(Into::into).collect())
                            })
                        } else {
                            <Option<Vec<MaybeReference<BlobId, String>>>>::parse(parser)?.map(
                                |ids| {
                                    MaybeReference::Value(ids.into_iter().map(Into::into).collect())
                                },
                            )
                        }
                    } else {
                        Some(MaybeReference::Reference(ResultReference::parse(parser)?))
                    };
                }
                0x7365_6974_7265_706f_7270 => {
                    request.properties = if !key.is_ref {
                        <Option<Vec<Property>>>::parse(parser)?.map(MaybeReference::Value)
                    } else {
                        Some(MaybeReference::Reference(ResultReference::parse(parser)?))
                    };
                }
                _ => {
                    if !request.arguments.parse(parser, key)? {
                        parser.skip_token(parser.depth_array, parser.depth_dict)?;
                    }
                }
            }
        }

        Ok(request)
    }
}

impl RequestPropertyParser for RequestArguments {
    fn parse(
        &mut self,
        parser: &mut Parser,
        property: RequestProperty,
    ) -> crate::parser::Result<bool> {
        match self {
            RequestArguments::Email(arguments) => arguments.parse(parser, property),
            RequestArguments::Blob(arguments) => arguments.parse(parser, property),
            _ => Ok(false),
        }
    }
}

impl GetRequest<RequestArguments> {
    pub fn take_arguments(&mut self) -> RequestArguments {
        std::mem::replace(&mut self.arguments, RequestArguments::VacationResponse)
    }

    pub fn with_arguments<T>(self, arguments: T) -> GetRequest<T> {
        GetRequest {
            arguments,
            account_id: self.account_id,
            ids: self.ids,
            properties: self.properties,
        }
    }
}

impl<T> GetRequest<T> {
    pub fn unwrap_properties(&mut self, default: &[Property]) -> Vec<Property> {
        if let Some(mut properties) = self.properties.take().map(|p| p.unwrap()) {
            // Add Id Property
            if !properties.contains(&Property::Id) {
                properties.push(Property::Id);
            }
            properties
        } else {
            default.to_vec()
        }
    }

    pub fn unwrap_ids(&mut self, max_objects_in_get: usize) -> trc::Result<Option<Vec<Id>>> {
        if let Some(ids) = self.ids.take() {
            let ids = ids.unwrap();
            if ids.len() <= max_objects_in_get {
                Ok(Some(
                    ids.into_iter()
                        .filter_map(|id| id.try_unwrap().and_then(|id| id.into_id()))
                        .collect::<Vec<_>>(),
                ))
            } else {
                Err(MethodError::RequestTooLarge.into())
            }
        } else {
            Ok(None)
        }
    }

    pub fn unwrap_blob_ids(
        &mut self,
        max_objects_in_get: usize,
    ) -> trc::Result<Option<Vec<BlobId>>> {
        if let Some(ids) = self.ids.take() {
            let ids = ids.unwrap();
            if ids.len() <= max_objects_in_get {
                Ok(Some(
                    ids.into_iter()
                        .filter_map(|id| id.try_unwrap().and_then(|id| id.into_blob_id()))
                        .collect::<Vec<_>>(),
                ))
            } else {
                Err(MethodError::RequestTooLarge.into())
            }
        } else {
            Ok(None)
        }
    }
}
