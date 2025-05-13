/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::types::{id::Id, property::Property};

#[derive(Debug, Clone, serde::Serialize)]
pub struct SetError {
    #[serde(rename = "type")]
    pub type_: SetErrorType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Cow<'static, str>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<InvalidProperty>>,

    #[serde(rename = "existingId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    existing_id: Option<Id>,
}

#[derive(Debug, Clone)]
pub enum InvalidProperty {
    Property(Property),
    Path(Vec<Property>),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum SetErrorType {
    #[serde(rename = "forbidden")]
    Forbidden,
    #[serde(rename = "overQuota")]
    OverQuota,
    #[serde(rename = "tooLarge")]
    TooLarge,
    #[serde(rename = "rateLimit")]
    RateLimit,
    #[serde(rename = "notFound")]
    NotFound,
    #[serde(rename = "invalidPatch")]
    InvalidPatch,
    #[serde(rename = "willDestroy")]
    WillDestroy,
    #[serde(rename = "invalidProperties")]
    InvalidProperties,
    #[serde(rename = "singleton")]
    Singleton,
    #[serde(rename = "mailboxHasChild")]
    MailboxHasChild,
    #[serde(rename = "mailboxHasEmail")]
    MailboxHasEmail,
    #[serde(rename = "blobNotFound")]
    BlobNotFound,
    #[serde(rename = "tooManyKeywords")]
    TooManyKeywords,
    #[serde(rename = "tooManyMailboxes")]
    TooManyMailboxes,
    #[serde(rename = "forbiddenFrom")]
    ForbiddenFrom,
    #[serde(rename = "invalidEmail")]
    InvalidEmail,
    #[serde(rename = "tooManyRecipients")]
    TooManyRecipients,
    #[serde(rename = "noRecipients")]
    NoRecipients,
    #[serde(rename = "invalidRecipients")]
    InvalidRecipients,
    #[serde(rename = "forbiddenMailFrom")]
    ForbiddenMailFrom,
    #[serde(rename = "forbiddenToSend")]
    ForbiddenToSend,
    #[serde(rename = "cannotUnsend")]
    CannotUnsend,
    #[serde(rename = "alreadyExists")]
    AlreadyExists,
    #[serde(rename = "invalidScript")]
    InvalidScript,
    #[serde(rename = "scriptIsActive")]
    ScriptIsActive,
}

impl SetErrorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SetErrorType::Forbidden => "forbidden",
            SetErrorType::OverQuota => "overQuota",
            SetErrorType::TooLarge => "tooLarge",
            SetErrorType::RateLimit => "rateLimit",
            SetErrorType::NotFound => "notFound",
            SetErrorType::InvalidPatch => "invalidPatch",
            SetErrorType::WillDestroy => "willDestroy",
            SetErrorType::InvalidProperties => "invalidProperties",
            SetErrorType::Singleton => "singleton",
            SetErrorType::BlobNotFound => "blobNotFound",
            SetErrorType::MailboxHasChild => "mailboxHasChild",
            SetErrorType::MailboxHasEmail => "mailboxHasEmail",
            SetErrorType::TooManyKeywords => "tooManyKeywords",
            SetErrorType::TooManyMailboxes => "tooManyMailboxes",
            SetErrorType::ForbiddenFrom => "forbiddenFrom",
            SetErrorType::InvalidEmail => "invalidEmail",
            SetErrorType::TooManyRecipients => "tooManyRecipients",
            SetErrorType::NoRecipients => "noRecipients",
            SetErrorType::InvalidRecipients => "invalidRecipients",
            SetErrorType::ForbiddenMailFrom => "forbiddenMailFrom",
            SetErrorType::ForbiddenToSend => "forbiddenToSend",
            SetErrorType::CannotUnsend => "cannotUnsend",
            SetErrorType::AlreadyExists => "alreadyExists",
            SetErrorType::InvalidScript => "invalidScript",
            SetErrorType::ScriptIsActive => "scriptIsActive",
        }
    }
}

impl SetError {
    pub fn new(type_: SetErrorType) -> Self {
        SetError {
            type_,
            description: None,
            properties: None,
            existing_id: None,
        }
    }

    pub fn with_description(mut self, description: impl Into<Cow<'static, str>>) -> Self {
        self.description = description.into().into();
        self
    }

    pub fn with_property(mut self, property: impl Into<InvalidProperty>) -> Self {
        self.properties = vec![property.into()].into();
        self
    }

    pub fn with_properties(
        mut self,
        properties: impl IntoIterator<Item = impl Into<InvalidProperty>>,
    ) -> Self {
        self.properties = properties
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>()
            .into();
        self
    }

    pub fn with_existing_id(mut self, id: Id) -> Self {
        self.existing_id = id.into();
        self
    }

    pub fn invalid_properties() -> Self {
        Self::new(SetErrorType::InvalidProperties)
    }

    pub fn forbidden() -> Self {
        Self::new(SetErrorType::Forbidden)
    }

    pub fn not_found() -> Self {
        Self::new(SetErrorType::NotFound)
    }

    pub fn blob_not_found() -> Self {
        Self::new(SetErrorType::BlobNotFound)
    }

    pub fn over_quota() -> Self {
        Self::new(SetErrorType::OverQuota).with_description("Account quota exceeded.")
    }

    pub fn already_exists() -> Self {
        Self::new(SetErrorType::AlreadyExists)
    }

    pub fn too_large() -> Self {
        Self::new(SetErrorType::TooLarge)
    }

    pub fn will_destroy() -> Self {
        Self::new(SetErrorType::WillDestroy).with_description("ID will be destroyed.")
    }
}

impl From<Property> for InvalidProperty {
    fn from(property: Property) -> Self {
        InvalidProperty::Property(property)
    }
}

impl From<(Property, Property)> for InvalidProperty {
    fn from((a, b): (Property, Property)) -> Self {
        InvalidProperty::Path(vec![a, b])
    }
}

impl serde::Serialize for InvalidProperty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            InvalidProperty::Property(p) => p.serialize(serializer),
            InvalidProperty::Path(p) => {
                use std::fmt::Write;
                let mut path = String::with_capacity(64);
                for (i, p) in p.iter().enumerate() {
                    if i > 0 {
                        path.push('/');
                    }
                    let _ = write!(path, "{}", p);
                }
                path.serialize(serializer)
            }
        }
    }
}
