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

use crate::{
    error::method::MethodError,
    object::{email, Object},
    parser::{json::Parser, Error, JsonObjectParser, Token},
    request::{
        method::MethodObject,
        reference::{MaybeReference, ResultReference},
        RequestProperty, RequestPropertyParser,
    },
    types::{id::Id, property::Property, state::State, value::Value},
};

#[derive(Debug, Clone)]
pub struct GetRequest<T> {
    pub account_id: Id,
    pub ids: Option<MaybeReference<Vec<Id>, ResultReference>>,
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
    pub not_found: Vec<Id>,
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
                        <Option<Vec<Id>>>::parse(parser)?.map(MaybeReference::Value)
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
        if let RequestArguments::Email(arguments) = self {
            arguments.parse(parser, property)
        } else {
            Ok(false)
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

    pub fn unwrap_ids(
        &mut self,
        max_objects_in_get: usize,
    ) -> Result<Option<Vec<Id>>, MethodError> {
        if let Some(ids) = self.ids.take() {
            let ids = ids.unwrap();
            if ids.len() <= max_objects_in_get {
                Ok(Some(ids))
            } else {
                Err(MethodError::RequestTooLarge)
            }
        } else {
            Ok(None)
        }
    }
}
