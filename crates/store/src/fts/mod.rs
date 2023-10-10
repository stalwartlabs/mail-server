/*
 * Copyright (c) 2023, Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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
    write::{BitmapFamily, Operation},
    BitmapKey, Serialize, BM_HASH,
};

use self::{bloom::hash_token, builder::MAX_TOKEN_MASK};

pub mod bloom;
pub mod builder;
pub mod query;
pub mod search_snippet;
pub mod term_index;

impl BitmapKey<Vec<u8>> {
    pub fn hash(word: &str, account_id: u32, collection: u8, family: u8, field: u8) -> Self {
        BitmapKey {
            account_id,
            collection,
            family: BM_HASH | family | (word.len() & MAX_TOKEN_MASK) as u8,
            field,
            block_num: 0,
            key: hash_token(word),
        }
    }

    pub fn value(
        account_id: u32,
        collection: impl Into<u8>,
        field: impl Into<u8>,
        value: impl BitmapFamily + Serialize,
    ) -> Self {
        BitmapKey {
            account_id,
            collection: collection.into(),
            family: value.family(),
            field: field.into(),
            block_num: 0,
            key: value.serialize(),
        }
    }
}

impl Operation {
    pub fn hash(word: &str, family: u8, field: u8, set: bool) -> Self {
        Operation::Bitmap {
            family: BM_HASH | family | (word.len() & MAX_TOKEN_MASK) as u8,
            field,
            key: hash_token(word),
            set,
        }
    }
}
