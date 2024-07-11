/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod lookup;
pub mod manage;

use std::{fmt::Display, slice::Iter, str::FromStr};

use store::{write::key::KeySerializer, Deserialize, Serialize, U32_LEN};
use utils::codec::leb128::Leb128Iterator;

use crate::{Principal, Type};

pub(super) struct PrincipalIdType {
    pub account_id: u32,
    pub typ: Type,
}

impl Serialize for Principal<u32> {
    fn serialize(self) -> Vec<u8> {
        (&self).serialize()
    }
}

impl Serialize for &Principal<u32> {
    fn serialize(self) -> Vec<u8> {
        let mut serializer = KeySerializer::new(
            U32_LEN * 3
                + 2
                + self.name.len()
                + self.emails.iter().map(|s| s.len()).sum::<usize>()
                + self.secrets.iter().map(|s| s.len()).sum::<usize>()
                + self.description.as_ref().map(|s| s.len()).unwrap_or(0),
        )
        .write(1u8)
        .write_leb128(self.id)
        .write(self.typ as u8)
        .write_leb128(self.quota)
        .write_leb128(self.name.len())
        .write(self.name.as_bytes())
        .write_leb128(self.description.as_ref().map_or(0, |s| s.len()))
        .write(self.description.as_deref().unwrap_or_default().as_bytes());

        for list in [&self.secrets, &self.emails] {
            serializer = serializer.write_leb128(list.len());
            for value in list {
                serializer = serializer.write_leb128(value.len()).write(value.as_bytes());
            }
        }

        serializer.finalize()
    }
}

impl Deserialize for Principal<u32> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        deserialize(bytes).ok_or_else(|| {
            trc::Cause::DataCorruption
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })
    }
}

impl Serialize for PrincipalIdType {
    fn serialize(self) -> Vec<u8> {
        KeySerializer::new(U32_LEN + 1)
            .write_leb128(self.account_id)
            .write(self.typ as u8)
            .finalize()
    }
}

impl Deserialize for PrincipalIdType {
    fn deserialize(bytes_: &[u8]) -> trc::Result<Self> {
        let mut bytes = bytes_.iter();
        Ok(PrincipalIdType {
            account_id: bytes.next_leb128().ok_or_else(|| {
                trc::Cause::DataCorruption
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, bytes_)
            })?,
            typ: Type::from_u8(*bytes.next().ok_or_else(|| {
                trc::Cause::DataCorruption
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, bytes_)
            })?),
        })
    }
}

impl PrincipalIdType {
    pub fn new(account_id: u32, typ: Type) -> Self {
        Self { account_id, typ }
    }
}

fn deserialize(bytes: &[u8]) -> Option<Principal<u32>> {
    let mut bytes = bytes.iter();
    if bytes.next()? != &1 {
        return None;
    }

    Principal {
        id: bytes.next_leb128()?,
        typ: Type::from_u8(*bytes.next()?),
        quota: bytes.next_leb128()?,
        name: deserialize_string(&mut bytes)?,
        description: deserialize_string(&mut bytes).map(|v| {
            if !v.is_empty() {
                Some(v)
            } else {
                None
            }
        })?,
        secrets: deserialize_string_list(&mut bytes)?,
        emails: deserialize_string_list(&mut bytes)?,
        member_of: Vec::new(),
    }
    .into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PrincipalField {
    #[serde(rename = "name")]
    Name,
    #[serde(rename = "type")]
    Type,
    #[serde(rename = "quota")]
    Quota,
    #[serde(rename = "description")]
    Description,
    #[serde(rename = "secrets")]
    Secrets,
    #[serde(rename = "emails")]
    Emails,
    #[serde(rename = "memberOf")]
    MemberOf,
    #[serde(rename = "members")]
    Members,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrincipalUpdate {
    pub action: PrincipalAction,
    pub field: PrincipalField,
    pub value: PrincipalValue,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PrincipalAction {
    #[serde(rename = "set")]
    Set,
    #[serde(rename = "addItem")]
    AddItem,
    #[serde(rename = "removeItem")]
    RemoveItem,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PrincipalValue {
    String(String),
    StringList(Vec<String>),
    Integer(u64),
}

impl PrincipalUpdate {
    pub fn set(field: PrincipalField, value: PrincipalValue) -> PrincipalUpdate {
        PrincipalUpdate {
            action: PrincipalAction::Set,
            field,
            value,
        }
    }

    pub fn add_item(field: PrincipalField, value: PrincipalValue) -> PrincipalUpdate {
        PrincipalUpdate {
            action: PrincipalAction::AddItem,
            field,
            value,
        }
    }

    pub fn remove_item(field: PrincipalField, value: PrincipalValue) -> PrincipalUpdate {
        PrincipalUpdate {
            action: PrincipalAction::RemoveItem,
            field,
            value,
        }
    }
}

impl Display for PrincipalField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl PrincipalField {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrincipalField::Name => "name",
            PrincipalField::Type => "type",
            PrincipalField::Quota => "quota",
            PrincipalField::Description => "description",
            PrincipalField::Secrets => "secrets",
            PrincipalField::Emails => "emails",
            PrincipalField::MemberOf => "memberOf",
            PrincipalField::Members => "members",
        }
    }
}

fn deserialize_string(bytes: &mut Iter<'_, u8>) -> Option<String> {
    let len = bytes.next_leb128()?;
    let mut string = Vec::with_capacity(len);
    for _ in 0..len {
        string.push(*bytes.next()?);
    }
    String::from_utf8(string).ok()
}

fn deserialize_string_list(bytes: &mut Iter<'_, u8>) -> Option<Vec<String>> {
    let len = bytes.next_leb128()?;
    let mut list = Vec::with_capacity(len);
    for _ in 0..len {
        list.push(deserialize_string(bytes)?);
    }
    Some(list)
}

impl Type {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "individual" => Some(Type::Individual),
            "superuser" => Some(Type::Superuser),
            "group" => Some(Type::Group),
            "resource" => Some(Type::Resource),
            "location" => Some(Type::Location),
            "list" => Some(Type::List),
            _ => None,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Type::Individual,
            1 => Type::Group,
            2 => Type::Resource,
            3 => Type::Location,
            4 => Type::Superuser,
            5 => Type::List,
            _ => Type::Other,
        }
    }

    pub fn into_base_type(self) -> Self {
        match self {
            Type::Superuser => Type::Individual,
            any => any,
        }
    }
}

impl FromStr for Type {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Type::parse(s).ok_or(())
    }
}

pub trait SpecialSecrets {
    fn is_disabled(&self) -> bool;
    fn is_otp_auth(&self) -> bool;
    fn is_app_password(&self) -> bool;
    fn is_password(&self) -> bool;
}

impl<T> SpecialSecrets for T
where
    T: AsRef<str>,
{
    fn is_disabled(&self) -> bool {
        self.as_ref() == "$disabled$"
    }

    fn is_otp_auth(&self) -> bool {
        self.as_ref().starts_with("otpauth://")
    }

    fn is_app_password(&self) -> bool {
        self.as_ref().starts_with("$app$")
    }

    fn is_password(&self) -> bool {
        !self.is_disabled() && !self.is_otp_auth() && !self.is_app_password()
    }
}
