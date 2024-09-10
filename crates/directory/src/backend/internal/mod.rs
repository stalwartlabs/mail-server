/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod lookup;
pub mod manage;

use std::{fmt::Display, slice::Iter, str::FromStr};

use ahash::AHashMap;
use store::{write::key::KeySerializer, Deserialize, Serialize, U32_LEN};
use utils::codec::leb128::Leb128Iterator;

use crate::{Principal, Type};

const INT_MARKER: u8 = 1 << 7;

pub(super) struct PrincipalIdType {
    pub account_id: u32,
    pub typ: Type,
}

impl Serialize for Principal {
    fn serialize(self) -> Vec<u8> {
        (&self).serialize()
    }
}

impl Serialize for &Principal {
    fn serialize(self) -> Vec<u8> {
        let mut serializer = KeySerializer::new(
            U32_LEN * 2
                + 2
                + self
                    .fields
                    .values()
                    .map(|v| v.serialized_size() + 1)
                    .sum::<usize>(),
        )
        .write(2u8)
        .write_leb128(self.id)
        .write(self.typ as u8)
        .write_leb128(self.fields.len());

        for (k, v) in &self.fields {
            let id = k.id();

            match v {
                PrincipalValue::String(v) => {
                    serializer = serializer
                        .write(id)
                        .write_leb128(1usize)
                        .write_leb128(v.len())
                        .write(v.as_bytes());
                }
                PrincipalValue::StringList(l) => {
                    serializer = serializer.write(id).write_leb128(l.len());
                    for v in l {
                        serializer = serializer.write_leb128(v.len()).write(v.as_bytes());
                    }
                }
                PrincipalValue::Integer(v) => {
                    serializer = serializer
                        .write(id | INT_MARKER)
                        .write_leb128(1usize)
                        .write_leb128(*v);
                }
                PrincipalValue::IntegerList(l) => {
                    serializer = serializer.write(id | INT_MARKER).write_leb128(l.len());
                    for v in l {
                        serializer = serializer.write_leb128(*v);
                    }
                }
            }
        }

        serializer.finalize()
    }
}

impl Deserialize for Principal {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        deserialize(bytes).ok_or_else(|| {
            trc::StoreEvent::DataCorruption
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
                trc::StoreEvent::DataCorruption
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, bytes_)
            })?,
            typ: Type::from_u8(*bytes.next().ok_or_else(|| {
                trc::StoreEvent::DataCorruption
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

fn deserialize(bytes: &[u8]) -> Option<Principal> {
    let mut bytes = bytes.iter();

    let version = *bytes.next()?;
    let id = bytes.next_leb128()?;
    let type_id = *bytes.next()?;
    let typ = Type::from_u8(type_id);

    match version {
        1 => {
            // Version 1 (legacy)
            let mut principal = Principal {
                id,
                typ,
                ..Default::default()
            };

            principal.set(PrincipalField::Quota, bytes.next_leb128::<u64>()?);
            principal.set(PrincipalField::Name, deserialize_string(&mut bytes)?);
            if let Some(description) = deserialize_string(&mut bytes).filter(|s| !s.is_empty()) {
                principal.set(PrincipalField::Description, description);
            }
            for key in [PrincipalField::Secrets, PrincipalField::Emails] {
                for _ in 0..bytes.next_leb128::<usize>()? {
                    principal.append_str(key, deserialize_string(&mut bytes)?);
                }
            }

            if type_id != 4 {
                principal
            } else {
                principal.into_superuser()
            }
            .into()
        }
        2 => {
            // Version 2
            let num_fields = bytes.next_leb128::<usize>()?;

            let mut principal = Principal {
                id,
                typ,
                fields: AHashMap::with_capacity(num_fields),
            };

            for _ in 0..num_fields {
                let id = *bytes.next()?;
                let num_values = bytes.next_leb128::<usize>()?;

                if (id & INT_MARKER) == 0 {
                    let field = PrincipalField::from_id(id)?;
                    if num_values == 1 {
                        principal.set(field, deserialize_string(&mut bytes)?);
                    } else {
                        let mut values = Vec::with_capacity(num_values);
                        for _ in 0..num_values {
                            values.push(deserialize_string(&mut bytes)?);
                        }
                        principal.set(field, values);
                    }
                } else {
                    let field = PrincipalField::from_id(id & !INT_MARKER)?;
                    if num_values == 1 {
                        principal.set(field, bytes.next_leb128::<u64>()?);
                    } else {
                        let mut values = Vec::with_capacity(num_values);
                        for _ in 0..num_values {
                            values.push(bytes.next_leb128::<u64>()?);
                        }
                        principal.set(field, values);
                    }
                }
            }

            principal.into()
        }
        _ => None,
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Hash, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
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
    IntegerList(Vec<u64>),
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
    pub fn id(&self) -> u8 {
        match self {
            PrincipalField::Name => 0,
            PrincipalField::Type => 1,
            PrincipalField::Quota => 2,
            PrincipalField::Description => 3,
            PrincipalField::Secrets => 4,
            PrincipalField::Emails => 5,
            PrincipalField::MemberOf => 6,
            PrincipalField::Members => 7,
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(PrincipalField::Name),
            1 => Some(PrincipalField::Type),
            2 => Some(PrincipalField::Quota),
            3 => Some(PrincipalField::Description),
            4 => Some(PrincipalField::Secrets),
            5 => Some(PrincipalField::Emails),
            6 => Some(PrincipalField::MemberOf),
            7 => Some(PrincipalField::Members),
            _ => None,
        }
    }

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

impl Type {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "individual" => Some(Type::Individual),
            "group" => Some(Type::Group),
            "resource" => Some(Type::Resource),
            "location" => Some(Type::Location),
            "list" => Some(Type::List),
            "tenant" => Some(Type::Tenant),
            "superuser" => Some(Type::Individual), // legacy
            _ => None,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Type::Individual,
            1 => Type::Group,
            2 => Type::Resource,
            3 => Type::Location,
            4 => Type::Individual, // legacy
            5 => Type::List,
            7 => Type::Tenant,
            _ => Type::Other,
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
    fn is_otp_auth(&self) -> bool;
    fn is_app_password(&self) -> bool;
    fn is_password(&self) -> bool;
}

impl<T> SpecialSecrets for T
where
    T: AsRef<str>,
{
    fn is_otp_auth(&self) -> bool {
        self.as_ref().starts_with("otpauth://")
    }

    fn is_app_password(&self) -> bool {
        self.as_ref().starts_with("$app$")
    }

    fn is_password(&self) -> bool {
        !self.is_otp_auth() && !self.is_app_password()
    }
}
