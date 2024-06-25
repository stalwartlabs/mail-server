/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::slice::Iter;

use store::{
    write::{
        BitmapClass, DeserializeFrom, MaybeDynamicId, Operation, SerializeInto, TagValue, ToBitmaps,
    },
    Serialize, U32_LEN,
};
use utils::codec::leb128::{Leb128Iterator, Leb128Vec};

pub mod get;
pub mod query;
pub mod set;

pub const INBOX_ID: u32 = 0;
pub const TRASH_ID: u32 = 1;
pub const JUNK_ID: u32 = 2;
pub const DRAFTS_ID: u32 = 3;
pub const SENT_ID: u32 = 4;
pub const ARCHIVE_ID: u32 = 5;
pub const TOMBSTONE_ID: u32 = u32::MAX - 1;

#[derive(Debug, Clone, Copy)]
pub struct UidMailbox {
    pub mailbox_id: u32,
    pub uid: u32,
}

impl PartialEq for UidMailbox {
    fn eq(&self, other: &Self) -> bool {
        self.mailbox_id == other.mailbox_id
    }
}

impl Eq for UidMailbox {}

impl ToBitmaps for UidMailbox {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        ops.push(Operation::Bitmap {
            class: BitmapClass::Tag {
                field,
                value: TagValue::Id(MaybeDynamicId::Static(self.mailbox_id)),
            },
            set,
        });
    }
}

impl SerializeInto for UidMailbox {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push_leb128(self.mailbox_id);
        buf.push_leb128(self.uid);
    }
}

impl DeserializeFrom for UidMailbox {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        Some(UidMailbox {
            mailbox_id: bytes.next_leb128()?,
            uid: bytes.next_leb128()?,
        })
    }
}

impl Serialize for UidMailbox {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(U32_LEN * 2);
        self.serialize_into(&mut buf);
        buf
    }
}

impl UidMailbox {
    pub fn new(mailbox_id: u32, uid: u32) -> Self {
        UidMailbox { mailbox_id, uid }
    }

    pub fn new_unassigned(mailbox_id: u32) -> Self {
        UidMailbox { mailbox_id, uid: 0 }
    }
}
