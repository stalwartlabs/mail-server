/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod index;
pub mod storage;

use calcard::vcard::VCard;
use common::DavName;
use dav_proto::schema::request::DeadProperty;
use jmap_proto::types::{acl::Acl, value::AclGrant};

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct AddressBook {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub sort_order: u32,
    pub is_default: bool,
    pub subscribers: Vec<u32>,
    pub dead_properties: DeadProperty,
    pub acls: Vec<AclGrant>,
    pub created: i64,
    pub modified: i64,
}

pub enum AddressBookRight {
    Read,
    Write,
    Share,
    Delete,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct ContactCard {
    pub names: Vec<DavName>,
    pub display_name: Option<String>,
    pub card: VCard,
    pub dead_properties: DeadProperty,
    pub created: i64,
    pub modified: i64,
    pub size: u32,
}

impl TryFrom<Acl> for AddressBookRight {
    type Error = Acl;

    fn try_from(value: Acl) -> Result<Self, Self::Error> {
        match value {
            Acl::Read => Ok(AddressBookRight::Read),
            Acl::Modify => Ok(AddressBookRight::Write),
            Acl::Share => Ok(AddressBookRight::Share),
            Acl::Delete => Ok(AddressBookRight::Delete),
            _ => Err(value),
        }
    }
}

impl From<AddressBookRight> for Acl {
    fn from(value: AddressBookRight) -> Self {
        match value {
            AddressBookRight::Read => Acl::Read,
            AddressBookRight::Write => Acl::Modify,
            AddressBookRight::Share => Acl::Share,
            AddressBookRight::Delete => Acl::Delete,
        }
    }
}
