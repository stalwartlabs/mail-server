/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod lookup;
pub mod manage;

use crate::Type;
use ahash::AHashMap;

use std::fmt::Display;
use store::{Deserialize, SerializeInfallible, U32_LEN, write::key::KeySerializer};
use utils::codec::leb128::Leb128Iterator;

pub struct PrincipalInfo {
    pub id: u32,
    pub typ: Type,
    pub tenant: Option<u32>,
}

#[cfg(feature = "enterprise")]
impl PrincipalInfo {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL

    pub fn has_tenant_access(&self, tenant_id: Option<u32>) -> bool {
        tenant_id.is_none_or(|tenant_id| {
            self.tenant.is_some_and(|t| tenant_id == t)
                || (self.typ == Type::Tenant && self.id == tenant_id)
        })
    }

    // SPDX-SnippetEnd
}

#[cfg(not(feature = "enterprise"))]
impl PrincipalInfo {
    pub fn has_tenant_access(&self, _tenant_id: Option<u32>) -> bool {
        true
    }
}

impl SerializeInfallible for PrincipalInfo {
    fn serialize(&self) -> Vec<u8> {
        if let Some(tenant) = self.tenant {
            KeySerializer::new((U32_LEN * 2) + 1)
                .write_leb128(self.id)
                .write(self.typ as u8)
                .write_leb128(tenant)
                .finalize()
        } else {
            KeySerializer::new(U32_LEN + 1)
                .write_leb128(self.id)
                .write(self.typ as u8)
                .finalize()
        }
    }
}

impl Deserialize for PrincipalInfo {
    fn deserialize(bytes_: &[u8]) -> trc::Result<Self> {
        let mut bytes = bytes_.iter();
        Ok(PrincipalInfo {
            id: bytes.next_leb128().ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, bytes_)
            })?,
            typ: Type::from_u8(*bytes.next().ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, bytes_)
            })?),
            tenant: bytes.next_leb128(),
        })
    }
}

impl PrincipalInfo {
    pub fn new(principal_id: u32, typ: Type, tenant: Option<u32>) -> Self {
        Self {
            id: principal_id,
            typ,
            tenant,
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Hash, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum PrincipalField {
    Name,
    Type,
    Quota,
    UsedQuota,
    Description,
    Secrets,
    Emails,
    MemberOf,
    Members,
    Tenant,
    Roles,
    Lists,
    EnabledPermissions,
    DisabledPermissions,
    Picture,
    Urls,
    ExternalMembers,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PrincipalSet {
    pub id: u32,
    pub typ: Type,
    pub fields: AHashMap<PrincipalField, PrincipalValue>,
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
            PrincipalField::Tenant => 8,
            PrincipalField::Roles => 9,
            PrincipalField::Lists => 10,
            PrincipalField::EnabledPermissions => 11,
            PrincipalField::DisabledPermissions => 12,
            PrincipalField::UsedQuota => 13,
            PrincipalField::Picture => 14,
            PrincipalField::Urls => 15,
            PrincipalField::ExternalMembers => 16,
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
            8 => Some(PrincipalField::Tenant),
            9 => Some(PrincipalField::Roles),
            10 => Some(PrincipalField::Lists),
            11 => Some(PrincipalField::EnabledPermissions),
            12 => Some(PrincipalField::DisabledPermissions),
            13 => Some(PrincipalField::UsedQuota),
            14 => Some(PrincipalField::Picture),
            15 => Some(PrincipalField::Urls),
            16 => Some(PrincipalField::ExternalMembers),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PrincipalField::Name => "name",
            PrincipalField::Type => "type",
            PrincipalField::Quota => "quota",
            PrincipalField::UsedQuota => "usedQuota",
            PrincipalField::Description => "description",
            PrincipalField::Secrets => "secrets",
            PrincipalField::Emails => "emails",
            PrincipalField::MemberOf => "memberOf",
            PrincipalField::Members => "members",
            PrincipalField::Tenant => "tenant",
            PrincipalField::Roles => "roles",
            PrincipalField::Lists => "lists",
            PrincipalField::EnabledPermissions => "enabledPermissions",
            PrincipalField::DisabledPermissions => "disabledPermissions",
            PrincipalField::Picture => "picture",
            PrincipalField::Urls => "urls",
            PrincipalField::ExternalMembers => "externalMembers",
        }
    }

    pub fn try_parse(s: &str) -> Option<Self> {
        match s {
            "name" => Some(PrincipalField::Name),
            "type" => Some(PrincipalField::Type),
            "quota" => Some(PrincipalField::Quota),
            "usedQuota" => Some(PrincipalField::UsedQuota),
            "description" => Some(PrincipalField::Description),
            "secrets" => Some(PrincipalField::Secrets),
            "emails" => Some(PrincipalField::Emails),
            "memberOf" => Some(PrincipalField::MemberOf),
            "members" => Some(PrincipalField::Members),
            "tenant" => Some(PrincipalField::Tenant),
            "roles" => Some(PrincipalField::Roles),
            "lists" => Some(PrincipalField::Lists),
            "enabledPermissions" => Some(PrincipalField::EnabledPermissions),
            "disabledPermissions" => Some(PrincipalField::DisabledPermissions),
            "picture" => Some(PrincipalField::Picture),
            "urls" => Some(PrincipalField::Urls),
            "externalMembers" => Some(PrincipalField::ExternalMembers),
            _ => None,
        }
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
