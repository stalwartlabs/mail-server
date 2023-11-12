/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use crate::{
    write::key::KeySerializer, AclKey, BitmapKey, BlobKey, IndexKey, LogKey, Serialize, ValueKey,
};

pub mod bitmap;
pub mod log;
pub mod main;
pub mod read;
pub mod write;

pub const CF_BITMAPS: &str = "b";
pub const CF_VALUES: &str = "v";
pub const CF_LOGS: &str = "l";
pub const CF_BLOBS: &str = "o";
pub const CF_INDEXES: &str = "i";

pub const COLLECTION_PREFIX_LEN: usize = U32_LEN + std::mem::size_of::<u8>();
pub const FIELD_PREFIX_LEN: usize = COLLECTION_PREFIX_LEN + std::mem::size_of::<u8>();
pub const ACCOUNT_KEY_LEN: usize = U32_LEN + std::mem::size_of::<u8>() + U32_LEN;

impl<T: AsRef<[u8]>> Serialize for IndexKey<T> {
    fn serialize(self) -> Vec<u8> {
        let key = self.key.as_ref();
        KeySerializer::new(std::mem::size_of::<IndexKey<T>>() + key.len())
            .write(self.account_id)
            .write(self.collection)
            .write(self.field)
            .write(key)
            .write(self.document_id)
            .finalize()
    }
}

impl Serialize for ValueKey {
    fn serialize(self) -> Vec<u8> {
        if self.family == 0 {
            KeySerializer::new(std::mem::size_of::<ValueKey>())
                .write_leb128(self.account_id)
                .write(self.collection)
                .write_leb128(self.document_id)
                .write(self.field)
                .finalize()
        } else {
            KeySerializer::new(std::mem::size_of::<ValueKey>() + 1)
                .write_leb128(self.account_id)
                .write(self.collection)
                .write_leb128(self.document_id)
                .write(u8::MAX)
                .write(self.family)
                .write(self.field)
                .finalize()
        }
    }
}

impl<T: AsRef<[u8]>> Serialize for BitmapKey<T> {
    fn serialize(self) -> Vec<u8> {
        let key = self.key.as_ref();
        KeySerializer::new(std::mem::size_of::<BitmapKey<T>>() + key.len())
            .write_leb128(self.account_id)
            .write(self.collection)
            .write(self.family)
            .write(self.field)
            .write(key)
            .finalize()
    }
}

impl<T: AsRef<[u8]>> Serialize for BlobKey<T> {
    fn serialize(self) -> Vec<u8> {
        let hash = self.hash.as_ref();
        KeySerializer::new(std::mem::size_of::<BlobKey<T>>() + hash.len())
            .write(hash)
            .write_leb128(self.account_id)
            .write(self.collection)
            .write_leb128(self.document_id)
            .finalize()
    }
}

impl Serialize for AclKey {
    fn serialize(self) -> Vec<u8> {
        KeySerializer::new(std::mem::size_of::<AclKey>())
            .write_leb128(self.grant_account_id)
            .write(u8::MAX)
            .write_leb128(self.to_account_id)
            .write(self.to_collection)
            .write_leb128(self.to_document_id)
            .finalize()
    }
}

impl Serialize for LogKey {
    fn serialize(self) -> Vec<u8> {
        KeySerializer::new(std::mem::size_of::<LogKey>())
            .write(self.account_id)
            .write(self.collection)
            .write(self.change_id)
            .finalize()
    }
}

impl BloomHash {
    pub fn to_high_rank_key(&self, account_id: u32, collection: u8, field: u8) -> Vec<u8> {
        KeySerializer::new(std::mem::size_of::<BitmapKey<&[u8]>>() + 2)
            .write_leb128(account_id)
            .write(collection)
            .write(BM_BLOOM)
            .write(field)
            .write(self.as_high_rank_hash())
            .finalize()
    }
}

impl From<rocksdb::Error> for crate::Error {
    fn from(value: rocksdb::Error) -> Self {
        Self::InternalError(format!("RocksDB error: {}", value))
    }
}
