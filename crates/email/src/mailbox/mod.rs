/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::jmap::settings::SpecialUse;
use jmap_proto::types::value::AclGrant;

pub mod destroy;
pub mod index;
pub mod manage;

pub const INBOX_ID: u32 = 0;
pub const TRASH_ID: u32 = 1;
pub const JUNK_ID: u32 = 2;
pub const DRAFTS_ID: u32 = 3;
pub const SENT_ID: u32 = 4;
pub const ARCHIVE_ID: u32 = 5;
pub const TOMBSTONE_ID: u32 = u32::MAX - 1;

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct Mailbox {
    pub name: String,
    pub role: SpecialUse,
    pub parent_id: u32,
    pub sort_order: Option<u32>,
    pub uid_validity: u32,
    pub subscribers: Vec<u32>,
    pub acls: Vec<AclGrant>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy)]
#[rkyv(derive(Debug, Clone, Copy))]
pub struct UidMailbox {
    pub mailbox_id: u32,
    pub uid: u32,
}

impl Mailbox {
    pub fn new(name: impl Into<String>) -> Self {
        Mailbox {
            name: name.into(),
            role: SpecialUse::None,
            parent_id: 0,
            sort_order: None,
            uid_validity: rand::random::<u32>(),
            subscribers: vec![],
            acls: vec![],
        }
    }

    pub fn with_role(mut self, role: SpecialUse) -> Self {
        self.role = role;
        self
    }

    pub fn with_parent_id(mut self, parent_id: u32) -> Self {
        self.parent_id = parent_id;
        self
    }

    pub fn with_sort_order(mut self, sort_order: u32) -> Self {
        self.sort_order = Some(sort_order);
        self
    }

    pub fn with_subscriber(mut self, subscriber: u32) -> Self {
        self.subscribers.push(subscriber);
        self
    }

    pub fn add_subscriber(&mut self, subscriber: u32) -> bool {
        if !self.subscribers.contains(&subscriber) {
            self.subscribers.push(subscriber);
            true
        } else {
            false
        }
    }

    pub fn remove_subscriber(&mut self, subscriber: u32) {
        self.subscribers.retain(|&x| x != subscriber);
    }

    pub fn is_subscribed(&self, subscriber: u32) -> bool {
        self.subscribers.contains(&subscriber)
    }
}

impl ArchivedMailbox {
    pub fn is_subscribed(&self, subscriber: u32) -> bool {
        self.subscribers.iter().any(|x| u32::from(x) == subscriber)
    }
}

impl PartialEq for UidMailbox {
    fn eq(&self, other: &Self) -> bool {
        self.mailbox_id == other.mailbox_id
    }
}

impl Eq for UidMailbox {}

impl UidMailbox {
    pub fn new(mailbox_id: u32, uid: u32) -> Self {
        UidMailbox { mailbox_id, uid }
    }

    pub fn new_unassigned(mailbox_id: u32) -> Self {
        UidMailbox { mailbox_id, uid: 0 }
    }
}
