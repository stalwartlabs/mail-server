/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::slice::Iter;

use store::{
    Serialize, U32_LEN,
    write::{DeserializeFrom, SerializeInto},
};
use utils::codec::leb128::{Leb128Iterator, Leb128Vec};

use super::{Mailbox, UidMailbox};

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
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(U32_LEN * 2);
        self.serialize_into(&mut buf);
        Ok(buf)
    }
}

impl Serialize for Mailbox {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(|r| r.into_vec())
            .map_err(Into::into)
    }
}
