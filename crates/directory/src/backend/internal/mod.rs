/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod lookup;
pub mod manage;

use std::{fmt::Display, slice::Iter};

use ahash::AHashMap;
use jmap_proto::types::collection::Collection;
use manage::DynamicPrincipalInfo;
use store::{
    write::{
        key::KeySerializer, AnyClass, BatchBuilder, DirectoryClass, MaybeDynamicId, ValueClass,
    },
    Deserialize, IterateParams, Serialize, Store, ValueKey, SUBSPACE_DIRECTORY, U32_LEN,
};
use trc::AddContext;
use utils::codec::leb128::{Leb128Iterator, Leb128Reader};

use crate::{Principal, Type, ROLE_ADMIN, ROLE_USER};

const INT_MARKER: u8 = 1 << 7;

pub struct PrincipalInfo {
    pub id: u32,
    pub typ: Type,
    pub tenant: Option<u32>,
}

impl Serialize for Principal {
    fn serialize(self) -> Vec<u8> {
        (&self).serialize()
    }
}

impl Serialize for &Principal {
    fn serialize(self) -> Vec<u8> {
        let mut serializer = KeySerializer::new(
            U32_LEN
                + 2
                + self
                    .fields
                    .values()
                    .map(|v| v.serialized_size() + 1)
                    .sum::<usize>(),
        )
        .write(2u8)
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

#[cfg(feature = "enterprise")]
impl PrincipalInfo {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL

    pub fn has_tenant_access(&self, tenant_id: Option<u32>) -> bool {
        tenant_id.map_or(true, |tenant_id| {
            self.tenant.map_or(false, |t| tenant_id == t)
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

impl Serialize for PrincipalInfo {
    fn serialize(self) -> Vec<u8> {
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

fn deserialize(bytes: &[u8]) -> Option<Principal> {
    let mut bytes = bytes.iter();

    match *bytes.next()? {
        1 => {
            // Version 1 (legacy)
            let id = bytes.next_leb128()?;
            let type_id = *bytes.next()?;

            let mut principal = Principal {
                id,
                typ: Type::from_u8(type_id),
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

            principal
                .with_field(
                    PrincipalField::Roles,
                    if type_id != 4 { ROLE_USER } else { ROLE_ADMIN },
                )
                .into()
        }
        2 => {
            // Version 2
            let typ = Type::from_u8(*bytes.next()?);
            let num_fields = bytes.next_leb128::<usize>()?;

            let mut principal = Principal {
                id: u32::MAX,
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

pub trait MigrateDirectory: Sync + Send {
    fn migrate_directory(&self) -> impl std::future::Future<Output = trc::Result<()>> + Send;
}

impl MigrateDirectory for Store {
    async fn migrate_directory(&self) -> trc::Result<()> {
        let mut principals = Vec::new();
        let mut domains = Vec::new();

        self.iterate(
            IterateParams::new(
                ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::Directory(DirectoryClass::Principal(0)),
                },
                ValueKey {
                    account_id: u32::MAX,
                    collection: u8::MAX,
                    document_id: u32::MAX,
                    class: ValueClass::Any(AnyClass {
                        subspace: SUBSPACE_DIRECTORY,
                        key: vec![4u8],
                    }),
                },
            ),
            |key, value| {
                match (key.first(), value.first()) {
                    (Some(2), Some(1)) => {
                        principals.push((
                            key.get(1..)
                                .and_then(|b| b.read_leb128::<u32>().map(|(v, _)| v))
                                .ok_or_else(|| {
                                    trc::StoreEvent::DataCorruption
                                        .caused_by(trc::location!())
                                        .ctx(trc::Key::Value, key)
                                })?,
                            Principal::deserialize(value)?,
                        ));
                    }
                    (Some(3), _) => {
                        let domain = std::str::from_utf8(&key[1..]).unwrap_or_default();
                        if !domain.is_empty() {
                            domains.push(domain.to_string());
                        }
                    }
                    _ => {}
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        let total_principal_count = principals.len();
        for (account_id, mut principal) in principals {
            let role = principal.take_int(PrincipalField::Roles).unwrap() as u32;

            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(u32::MAX)
                .with_collection(Collection::Principal)
                .set(
                    ValueClass::Directory(DirectoryClass::Principal(MaybeDynamicId::Static(
                        account_id,
                    ))),
                    (&principal).serialize(),
                );

            if principal.typ() == Type::Individual {
                batch
                    .set(
                        ValueClass::Directory(DirectoryClass::MemberOf {
                            principal_id: MaybeDynamicId::Static(account_id),
                            member_of: MaybeDynamicId::Static(role),
                        }),
                        vec![Type::Role as u8],
                    )
                    .set(
                        ValueClass::Directory(DirectoryClass::Members {
                            principal_id: MaybeDynamicId::Static(role),
                            has_member: MaybeDynamicId::Static(account_id),
                        }),
                        vec![],
                    );
            }

            self.write(batch.build())
                .await
                .caused_by(trc::location!())?;
        }

        let total_domain_count = domains.len();
        for domain in domains {
            let mut batch = BatchBuilder::new();

            batch
                .with_account_id(u32::MAX)
                .with_collection(Collection::Principal)
                .create_document()
                .assert_value(
                    ValueClass::Directory(DirectoryClass::NameToId(
                        domain.to_string().into_bytes(),
                    )),
                    (),
                )
                .set(
                    ValueClass::Directory(DirectoryClass::Principal(MaybeDynamicId::Dynamic(0))),
                    Principal::new(0, Type::Domain)
                        .with_field(PrincipalField::Name, domain.to_string())
                        .with_field(PrincipalField::Description, domain.to_string())
                        .serialize(),
                )
                .set(
                    ValueClass::Directory(DirectoryClass::NameToId(domain.as_bytes().to_vec())),
                    DynamicPrincipalInfo::new(Type::Domain, None),
                )
                .clear(ValueClass::Any(AnyClass {
                    subspace: SUBSPACE_DIRECTORY,
                    key: [3u8].iter().chain(domain.as_bytes()).copied().collect(),
                }));

            self.write(batch.build())
                .await
                .caused_by(trc::location!())?;
        }

        if total_domain_count > 0 || total_principal_count > 0 {
            trc::event!(
                Server(trc::ServerEvent::Startup),
                Details = format!(
                    "Migrated {total_principal_count} principals and {total_domain_count} domains",
                )
            );
        }

        Ok(())
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
            _ => None,
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
