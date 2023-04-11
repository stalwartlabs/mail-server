use ahash::AHashMap;
use utils::map::vec_map::VecMap;

use crate::{
    error::{method::MethodError, set::SetError},
    object::{email_submission, mailbox, sieve, Object},
    parser::{json::Parser, Error, JsonObjectParser, Token},
    request::{
        method::MethodObject,
        reference::{MaybeReference, ResultReference},
        RequestProperty, RequestPropertyParser,
    },
    types::{
        acl::Acl,
        blob::BlobId,
        date::UTCDate,
        id::Id,
        keyword::Keyword,
        property::{HeaderForm, ObjectProperty, Property, SetProperty},
        state::State,
        type_state::TypeState,
        value::{SetValue, SetValueMap, Value},
    },
};

use super::ahash_is_empty;

#[derive(Debug, Clone)]
pub struct SetRequest {
    pub account_id: Id,
    pub if_in_state: Option<State>,
    pub create: Option<VecMap<String, Object<SetValue>>>,
    pub update: Option<VecMap<Id, Object<SetValue>>>,
    pub destroy: Option<MaybeReference<Vec<Id>, ResultReference>>,
    pub arguments: RequestArguments,
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
    Principal,
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
}

impl JsonObjectParser for SetRequest {
    fn parse(parser: &mut Parser) -> crate::parser::Result<Self>
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
                MethodObject::Principal => RequestArguments::Principal,
                _ => {
                    return Err(Error::Method(MethodError::UnknownMethod(format!(
                        "{}/set",
                        parser.ctx
                    ))))
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

        while {
            let property = parser.next_dict_key::<RequestProperty>()?;
            match &property.hash[0] {
                0x6449_746e_756f_6363_61 if !property.is_ref => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x6574_6165_7263 if !property.is_ref => {
                    request.create = <Option<VecMap<String, Object<SetValue>>>>::parse(parser)?;
                }
                0x6574_6164_7075 if !property.is_ref => {
                    request.update = <Option<VecMap<Id, Object<SetValue>>>>::parse(parser)?;
                }
                0x0079_6f72_7473_6564 => {
                    request.destroy = if !property.is_ref {
                        <Option<Vec<Id>>>::parse(parser)?.map(MaybeReference::Value)
                    } else {
                        Some(MaybeReference::Reference(ResultReference::parse(parser)?))
                    };
                }
                0x6574_6174_536e_4966_69 if !property.is_ref => {
                    request.if_in_state = parser
                        .next_token::<State>()?
                        .unwrap_string_or_null("ifInState")?;
                }
                _ => {
                    if !request.arguments.parse(parser, property)? {
                        parser.skip_token(parser.depth_array, parser.depth_dict)?;
                    }
                }
            }

            !parser.is_dict_end()?
        } {}

        Ok(request)
    }
}

impl JsonObjectParser for Object<SetValue> {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut obj = Object {
            properties: VecMap::with_capacity(8),
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while {
            let mut property = parser.next_dict_key::<SetProperty>()?;
            let value = if !property.is_ref {
                match &property.property {
                    Property::Id | Property::ThreadId => parser
                        .next_token::<Id>()?
                        .unwrap_string_or_null("")?
                        .map(|id| SetValue::Value(Value::Id(id)))
                        .unwrap_or(SetValue::Value(Value::Null)),
                    Property::BlobId | Property::Picture => parser
                        .next_token::<BlobId>()?
                        .unwrap_string_or_null("")?
                        .map(|id| SetValue::Value(Value::BlobId(id)))
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
                            SetValue::Value(Value::parse::<ObjectProperty, String>(parser)?)
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
                        .map(SetValue::IdReference)
                        .unwrap_or(SetValue::Value(Value::Null)),
                    Property::MailboxIds => {
                        if property.patch.is_empty() {
                            SetValue::IdReferences(
                                <SetValueMap<MaybeReference<Id, String>>>::parse(parser)?.values,
                            )
                        } else {
                            property.patch.push(Value::Bool(bool::parse(parser)?));
                            SetValue::Patch(property.patch)
                        }
                    }
                    Property::Keywords => {
                        if property.patch.is_empty() {
                            SetValue::Value(Value::List(
                                <SetValueMap<Keyword>>::parse(parser)?
                                    .values
                                    .into_iter()
                                    .map(Value::Keyword)
                                    .collect(),
                            ))
                        } else {
                            property.patch.push(Value::Bool(bool::parse(parser)?));
                            SetValue::Patch(property.patch)
                        }
                    }

                    Property::Acl => SetValue::Value(Value::parse::<String, Acl>(parser)?),
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
                    | Property::UndoStatus => {
                        SetValue::Value(Value::parse::<ObjectProperty, String>(parser)?)
                    }
                    Property::Members => {
                        SetValue::Value(Value::parse::<ObjectProperty, Id>(parser)?)
                    }
                    Property::Header(h) => SetValue::Value(if matches!(h.form, HeaderForm::Date) {
                        Value::parse::<ObjectProperty, UTCDate>(parser)
                    } else {
                        Value::parse::<ObjectProperty, String>(parser)
                    }?),
                    Property::Types => {
                        SetValue::Value(Value::parse::<ObjectProperty, TypeState>(parser)?)
                    }
                    _ => {
                        parser.skip_token(parser.depth_array, parser.depth_dict)?;
                        SetValue::Value(Value::Null)
                    }
                }
            } else {
                SetValue::ResultReference(ResultReference::parse(parser)?)
            };

            obj.properties.append(property.property, value);

            !parser.is_dict_end()?
        } {}

        Ok(obj)
    }
}

impl RequestPropertyParser for RequestArguments {
    fn parse(
        &mut self,
        parser: &mut Parser,
        property: RequestProperty,
    ) -> crate::parser::Result<bool> {
        match self {
            RequestArguments::Mailbox(args) => args.parse(parser, property),
            RequestArguments::EmailSubmission(args) => args.parse(parser, property),
            RequestArguments::SieveScript(args) => args.parse(parser, property),
            _ => Ok(false),
        }
    }
}
