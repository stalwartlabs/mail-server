/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::vcard::VCard;
use jmap_proto::types::{acl::Acl, value::AclGrant};

pub struct AddressBook {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub sort_order: u32,
    pub is_default: bool,
    pub subscribers: Vec<u32>,
    pub acls: Vec<AclGrant>,
}

pub enum AddressBookRight {
    Read,
    Write,
    Share,
    Delete,
}

pub struct ContactCard {
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub addressbook_ids: Vec<u32>,
    pub card: VCard,
    pub created: u64,
    pub updated: u64,
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
