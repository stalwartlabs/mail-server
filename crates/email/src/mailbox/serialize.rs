/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use std::slice::Iter;

use store::{
    Deserialize, Serialize, U32_LEN,
    write::{
        BitmapClass, DeserializeFrom, MaybeDynamicId, Operation, SerializeInto, TagValue, ToBitmaps,
    },
};
use utils::codec::leb128::{Leb128Iterator, Leb128Vec};

use super::{Mailbox, UidMailbox};

impl Serialize for Mailbox {
    fn serialize(self) -> Vec<u8> {
        let todo = 1;
        todo!()
    }
}

impl Deserialize for Mailbox {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let todo = 1;
        todo!()
    }
}

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
