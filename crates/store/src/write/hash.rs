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

use crate::backend::MAX_TOKEN_LENGTH;

use super::{BitmapClass, BitmapHash};

impl BitmapClass {
    pub fn word(token: impl AsRef<[u8]>, field: impl Into<u8>) -> Self {
        BitmapClass::Text {
            field: field.into(),
            token: BitmapHash::new(token),
        }
    }

    pub fn stemmed(token: impl AsRef<[u8]>, field: impl Into<u8>) -> Self {
        BitmapClass::Text {
            field: field.into() | 1 << 7,
            token: BitmapHash::new(token),
        }
    }

    /*pub fn bigram(token: impl AsRef<[u8]>, field: impl Into<u8>) -> Self {
        BitmapClass::Text {
            field: field.into() | 1 << 7,
            token: BitmapHash::new(token),
        }
    }*/
}

impl BitmapHash {
    pub fn new(item: impl AsRef<[u8]>) -> Self {
        Self {
            len: std::cmp::min(item.as_ref().len(), MAX_TOKEN_LENGTH) as u8,
            hash: hash(item),
        }
    }

    pub fn to_u64(&self) -> u64 {
        u64::from_be_bytes(self.hash)
    }
}

fn hash(item: impl AsRef<[u8]>) -> [u8; 8] {
    let item = item.as_ref();
    let mut result = [0u8; 8];

    if item.len() <= 8 {
        result[..item.len()].copy_from_slice(item);
    } else {
        result[..4].copy_from_slice(&xxhash_rust::xxh3::xxh3_64(item).to_le_bytes()[..4]);
        result[4..8].copy_from_slice(&farmhash::hash64(item).to_le_bytes()[..4]);
    }

    result
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct TokenType {}

impl TokenType {
    pub fn word(field: u8) -> u8 {
        field
    }

    pub fn stemmed(field: u8) -> u8 {
        1 << 7 | field
    }

    /*pub fn bigram(field: u8) -> u8 {
        1 << 7 | field
    }*/
}
