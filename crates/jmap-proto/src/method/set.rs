/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use utils::map::{bitmap::Bitmap, vec_map::VecMap};

use crate::{
    error::set::{InvalidProperty, SetError},
    object::{email_submission, mailbox, sieve, Object},
    parser::{json::Parser, JsonObjectParser, Token},
    request::{
        method::MethodObject,
        reference::{MaybeReference, ResultReference},
        RequestProperty, RequestPropertyParser,
    },
    response::Response,
    types::{
        acl::Acl,
        any_id::AnyId,
        blob::BlobId,
        date::UTCDate,
        id::Id,
        keyword::Keyword,
        property::{HeaderForm, ObjectProperty, Property, SetProperty},
        state::{State, StateChange},
        value::{SetValue, SetValueMap, Value},
    },
};

use super::ahash_is_empty;

#[derive(Debug, Clone)]
pub struct SetRequest<T> {
    pub account_id: Id,
    pub if_in_state: Option<State>,
    pub create: Option<VecMap<String, Object<SetValue>>>,
    pub update: Option<VecMap<Id, Object<SetValue>>>,
    pub destroy: Option<MaybeReference<Vec<Id>, ResultReference>>,
    pub arguments: T,
}

#[derive(Debug, Clone)]
pub enum RequestArguments {
    Email,
    Mailbox(mailbox::SetArguments),
    Identity,
    EmailSubmission(email_submission::SetArguments),
    PushSubscription,
    SieveScript(sieve::SetArguments),
    VacationResponse,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SetResponse {
    #[serde(rename = "accountId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<Id>,

    #[serde(rename = "oldState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_state: Option<State>,

    #[serde(rename = "newState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_state: Option<State>,

    #[serde(rename = "created")]
    #[serde(skip_serializing_if = "ahash_is_empty")]
    pub created: AHashMap<String, Object<Value>>,

    #[serde(rename = "updated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub updated: VecMap<Id, Option<Object<Value>>>,

    #[serde(rename = "destroyed")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub destroyed: Vec<Id>,

    #[serde(rename = "notCreated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_created: VecMap<String, SetError>,

    #[serde(rename = "notUpdated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_updated: VecMap<Id, SetError>,

    #[serde(rename = "notDestroyed")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_destroyed: VecMap<Id, SetError>,

    #[serde(skip)]
    pub state_change: Option<StateChange>,
}

impl JsonObjectParser for SetRequest<RequestArguments> {
    fn parse(parser: &mut Parser) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut request = SetRequest {
            arguments: match &parser.ctx {
                MethodObject::Email => RequestArguments::Email,
                MethodObject::Mailbox => RequestArguments::Mailbox(Default::default()),
                MethodObject::Identity => RequestArguments::Identity,
                MethodObject::EmailSubmission => {
                    RequestArguments::EmailSubmission(Default::default())
                }
                MethodObject::PushSubscription => RequestArguments::PushSubscription,
                MethodObject::VacationResponse => RequestArguments::VacationResponse,
                MethodObject::SieveScript => RequestArguments::SieveScript(Default::default()),
                _ => {
                    return Err(trc::JmapCause::UnknownMethod
                        .into_err()
                        .details(format!("{}/set", parser.ctx)))
                }
            },
            account_id: Id::default(),
            if_in_state: None,
            create: None,
            update: None,
            destroy: None,
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x0064_4974_6e75_6f63_6361 if !key.is_ref => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x6574_6165_7263 if !key.is_ref => {
                    request.create = <Option<VecMap<String, Object<SetValue>>>>::parse(parser)?;
                }
                0x6574_6164_7075 if !key.is_ref => {
                    request.update = <Option<VecMap<Id, Object<SetValue>>>>::parse(parser)?;
                }
                0x0079_6f72_7473_6564 => {
                    request.destroy = if !key.is_ref {
                        <Option<Vec<Id>>>::parse(parser)?.map(MaybeReference::Value)
                    } else {
                        Some(MaybeReference::Reference(ResultReference::parse(parser)?))
                    };
                }
                0x0065_7461_7453_6e49_6669 if !key.is_ref => {
                    request.if_in_state = parser
                        .next_token::<State>()?
                        .unwrap_string_or_null("ifInState")?;
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

impl JsonObjectParser for Object<SetValue> {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut obj = Object {
            properties: VecMap::with_capacity(8),
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(mut key) = parser.next_dict_key::<SetProperty>()? {
            let value = if !key.is_ref {
                match &key.property {
                    Property::Id | Property::ThreadId => parser
                        .next_token::<Id>()?
                        .unwrap_string_or_null("")?
                        .map(|id| SetValue::Value(Value::Id(id)))
                        .unwrap_or(SetValue::Value(Value::Null)),
                    Property::BlobId | Property::Picture => parser
                        .next_token::<MaybeReference<BlobId, String>>()?
                        .unwrap_string_or_null("")?
                        .map(SetValue::from)
                        .unwrap_or(SetValue::Value(Value::Null)),
                    Property::SentAt
                    | Property::ReceivedAt
                    | Property::Expires
                    | Property::FromDate
                    | Property::ToDate => parser
                        .next_token::<UTCDate>()?
                        .unwrap_string_or_null("")?
                        .map(|date| SetValue::Value(Value::Date(date)))
                        .unwrap_or(SetValue::Value(Value::Null)),
                    Property::Subject
                    | Property::Preview
                    | Property::Name
                    | Property::Description
                    | Property::Timezone
                    | Property::Email
                    | Property::Secret
                    | Property::DeviceClientId
                    | Property::Url
                    | Property::VerificationCode
                    | Property::HtmlSignature
                    | Property::TextSignature
                    | Property::Type
                    | Property::Charset
                    | Property::Disposition
                    | Property::Language
                    | Property::Location
                    | Property::Cid
                    | Property::Role
                    | Property::PartId => parser
                        .next_token::<String>()?
                        .unwrap_string_or_null("")?
                        .map(|text| SetValue::Value(Value::Text(text)))
                        .unwrap_or(SetValue::Value(Value::Null)),
                    Property::TextBody | Property::HtmlBody => {
                        if let MethodObject::Email = &parser.ctx {
                            SetValue::Value(Value::parse::<ObjectProperty, String>(
                                parser.next_token()?,
                                parser,
                            )?)
                        } else {
                            parser
                                .next_token::<String>()?
                                .unwrap_string_or_null("")?
                                .map(|text| SetValue::Value(Value::Text(text)))
                                .unwrap_or(SetValue::Value(Value::Null))
                        }
                    }
                    Property::HasAttachment
                    | Property::IsSubscribed
                    | Property::IsEnabled
                    | Property::IsActive => parser
                        .next_token::<String>()?
                        .unwrap_bool_or_null("")?
                        .map(|bool| SetValue::Value(Value::Bool(bool)))
                        .unwrap_or(SetValue::Value(Value::Null)),
                    Property::Size | Property::SortOrder | Property::Quota => parser
                        .next_token::<String>()?
                        .unwrap_uint_or_null("")?
                        .map(|uint| SetValue::Value(Value::UnsignedInt(uint)))
                        .unwrap_or(SetValue::Value(Value::Null)),
                    Property::ParentId | Property::EmailId | Property::IdentityId => parser
                        .next_token::<MaybeReference<Id, String>>()?
                        .unwrap_string_or_null("")?
                        .map(SetValue::from)
                        .unwrap_or(SetValue::Value(Value::Null)),
                    Property::MailboxIds => {
                        if key.patch.is_empty() {
                            SetValue::from(
                                <SetValueMap<MaybeReference<Id, String>>>::parse(parser)?.values,
                            )
                        } else {
                            key.patch.push(Value::Bool(bool::parse(parser)?));
                            SetValue::Patch(key.patch)
                        }
                    }
                    Property::Keywords => {
                        if key.patch.is_empty() {
                            SetValue::Value(Value::List(
                                <SetValueMap<Keyword>>::parse(parser)?
                                    .values
                                    .into_iter()
                                    .map(Value::Keyword)
                                    .collect(),
                            ))
                        } else {
                            key.patch.push(Value::Bool(bool::parse(parser)?));
                            SetValue::Patch(key.patch)
                        }
                    }

                    Property::Acl => match key.patch.len() {
                        0 => {
                            parser
                                .next_token::<String>()?
                                .assert_jmap(Token::DictStart)?;
                            let mut acls = Vec::new();
                            while let Some(account) = parser.next_dict_key::<String>()? {
                                acls.push(Value::Text(account));
                                acls.push(Value::UnsignedInt(<Bitmap<Acl>>::parse(parser)?.into()));
                            }
                            SetValue::Value(Value::List(acls))
                        }
                        1 => {
                            key.patch
                                .push(Value::UnsignedInt(<Bitmap<Acl>>::parse(parser)?.into()));
                            SetValue::Patch(key.patch)
                        }
                        2 => {
                            key.patch.push(Value::Bool(bool::parse(parser)?));
                            SetValue::Patch(key.patch)
                        }
                        _ => unreachable!(),
                    },
                    Property::Aliases
                    | Property::Attachments
                    | Property::Bcc
                    | Property::BodyStructure
                    | Property::BodyValues
                    | Property::Capabilities
                    | Property::Cc
                    | Property::Envelope
                    | Property::From
                    | Property::Headers
                    | Property::InReplyTo
                    | Property::Keys
                    | Property::MessageId
                    | Property::References
                    | Property::ReplyTo
                    | Property::Sender
                    | Property::SubParts
                    | Property::To
                    | Property::UndoStatus
                    | Property::Types => SetValue::Value(Value::parse::<ObjectProperty, String>(
                        parser.next_token()?,
                        parser,
                    )?),
                    Property::Parameters => SetValue::Value(Value::parse::<String, String>(
                        parser.next_token()?,
                        parser,
                    )?),
                    Property::Members => SetValue::Value(Value::parse::<ObjectProperty, Id>(
                        parser.next_token()?,
                        parser,
                    )?),
                    Property::Header(h) => SetValue::Value(if matches!(h.form, HeaderForm::Date) {
                        Value::parse::<ObjectProperty, UTCDate>(parser.next_token()?, parser)
                    } else {
                        Value::parse::<ObjectProperty, String>(parser.next_token()?, parser)
                    }?),

                    _ => {
                        parser.skip_token(parser.depth_array, parser.depth_dict)?;
                        SetValue::Value(Value::Null)
                    }
                }
            } else {
                SetValue::ResultReference(ResultReference::parse(parser)?)
            };

            obj.properties.append(key.property, value);
        }

        Ok(obj)
    }
}

impl<T: Into<AnyId>> From<MaybeReference<T, String>> for SetValue {
    fn from(reference: MaybeReference<T, String>) -> Self {
        match reference {
            MaybeReference::Value(id) => SetValue::IdReference(MaybeReference::Value(id.into())),
            MaybeReference::Reference(reference) => {
                SetValue::IdReference(MaybeReference::Reference(reference))
            }
        }
    }
}

impl<T: Into<AnyId>> From<Vec<MaybeReference<T, String>>> for SetValue {
    fn from(value: Vec<MaybeReference<T, String>>) -> Self {
        SetValue::IdReferences(
            value
                .into_iter()
                .map(|reference| match reference {
                    MaybeReference::Value(id) => MaybeReference::Value(id.into()),
                    MaybeReference::Reference(reference) => MaybeReference::Reference(reference),
                })
                .collect(),
        )
    }
}

impl RequestPropertyParser for RequestArguments {
    fn parse(&mut self, parser: &mut Parser, property: RequestProperty) -> trc::Result<bool> {
        match self {
            RequestArguments::Mailbox(args) => args.parse(parser, property),
            RequestArguments::EmailSubmission(args) => args.parse(parser, property),
            RequestArguments::SieveScript(args) => args.parse(parser, property),
            _ => Ok(false),
        }
    }
}

impl<T> SetRequest<T> {
    pub fn validate(&self, max_objects_in_set: usize) -> trc::Result<()> {
        if self.create.as_ref().map_or(0, |objs| objs.len())
            + self.update.as_ref().map_or(0, |objs| objs.len())
            + self.destroy.as_ref().map_or(0, |objs| {
                if let MaybeReference::Value(ids) = objs {
                    ids.len()
                } else {
                    0
                }
            })
            > max_objects_in_set
        {
            Err(trc::JmapCause::RequestTooLarge.into_err())
        } else {
            Ok(())
        }
    }

    pub fn has_updates(&self) -> bool {
        self.update.as_ref().map_or(false, |objs| !objs.is_empty())
    }

    pub fn has_creates(&self) -> bool {
        self.create.as_ref().map_or(false, |objs| !objs.is_empty())
    }

    pub fn unwrap_create(&mut self) -> VecMap<String, Object<SetValue>> {
        self.create.take().unwrap_or_default()
    }

    pub fn unwrap_update(&mut self) -> VecMap<Id, Object<SetValue>> {
        self.update.take().unwrap_or_default()
    }

    pub fn unwrap_destroy(&mut self) -> Vec<Id> {
        self.destroy
            .take()
            .map(|ids| ids.unwrap())
            .unwrap_or_default()
    }
}

impl SetRequest<RequestArguments> {
    pub fn take_arguments(&mut self) -> RequestArguments {
        std::mem::replace(&mut self.arguments, RequestArguments::VacationResponse)
    }

    pub fn with_arguments<T>(self, arguments: T) -> SetRequest<T> {
        SetRequest {
            account_id: self.account_id,
            if_in_state: self.if_in_state,
            create: self.create,
            update: self.update,
            destroy: self.destroy,
            arguments,
        }
    }
}

impl SetResponse {
    pub fn from_request<T>(request: &SetRequest<T>, max_objects: usize) -> trc::Result<Self> {
        let n_create = request.create.as_ref().map_or(0, |objs| objs.len());
        let n_update = request.update.as_ref().map_or(0, |objs| objs.len());
        let n_destroy = request.destroy.as_ref().map_or(0, |objs| {
            if let MaybeReference::Value(ids) = objs {
                ids.len()
            } else {
                0
            }
        });
        if n_create + n_update + n_destroy <= max_objects {
            Ok(SetResponse {
                account_id: if request.account_id.is_valid() {
                    request.account_id.into()
                } else {
                    None
                },
                new_state: None,
                old_state: None,
                created: AHashMap::with_capacity(n_create),
                updated: VecMap::with_capacity(n_update),
                destroyed: Vec::with_capacity(n_destroy),
                not_created: VecMap::new(),
                not_updated: VecMap::new(),
                not_destroyed: VecMap::new(),
                state_change: None,
            })
        } else {
            Err(trc::JmapCause::RequestTooLarge.into_err())
        }
    }

    pub fn with_state(mut self, state: State) -> Self {
        self.old_state = Some(state.clone());
        self.new_state = Some(state);
        self
    }

    pub fn created(&mut self, id: String, document_id: u32) {
        self.created.insert(
            id,
            Object::with_capacity(1).with_property(Property::Id, Value::Id(document_id.into())),
        );
    }

    pub fn invalid_property_create(&mut self, id: String, property: impl Into<InvalidProperty>) {
        self.not_created.append(
            id,
            SetError::invalid_properties()
                .with_property(property)
                .with_description("Invalid property or value.".to_string()),
        );
    }

    pub fn invalid_property_update(&mut self, id: Id, property: impl Into<InvalidProperty>) {
        self.not_updated.append(
            id,
            SetError::invalid_properties()
                .with_property(property)
                .with_description("Invalid property or value.".to_string()),
        );
    }

    pub fn update_created_ids(&self, response: &mut Response) {
        for (user_id, obj) in &self.created {
            if let Some(id) = obj.get(&Property::Id).as_id() {
                response.created_ids.insert(user_id.clone(), (*id).into());
            }
        }
    }

    pub fn get_object_by_id(&mut self, id: Id) -> Option<&mut Object<Value>> {
        if let Some(obj) = self.updated.get_mut(&id) {
            if let Some(obj) = obj {
                return Some(obj);
            } else {
                *obj = Some(Object::with_capacity(1));
                return obj.as_mut().unwrap().into();
            }
        }

        (&mut self.created)
            .into_iter()
            .map(|(_, obj)| obj)
            .find(|obj| obj.properties.get(&Property::Id) == Some(&Value::Id(id)))
    }

    pub fn has_changes(&self) -> bool {
        !self.created.is_empty() || !self.updated.is_empty() || !self.destroyed.is_empty()
    }
}
