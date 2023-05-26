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

use rocksdb::{Direction, IteratorMode};

use crate::{
    query::log::{Changes, Query},
    write::key::DeserializeBigEndian,
    Error, LogKey, Serialize, Store,
};

use super::CF_LOGS;

const CHANGE_ID_POS: usize = std::mem::size_of::<u32>() + std::mem::size_of::<u8>();

impl Store {
    pub fn get_last_change_id(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
    ) -> crate::Result<Option<u64>> {
        let collection = collection.into();
        let match_key = LogKey {
            account_id,
            collection,
            change_id: u64::MAX,
        }
        .serialize();

        if let Some(Ok((key, _))) = self
            .db
            .iterator_cf(
                &self.db.cf_handle(CF_LOGS).unwrap(),
                IteratorMode::From(&match_key, Direction::Reverse),
            )
            .next()
        {
            if key.starts_with(&match_key[0..CHANGE_ID_POS]) {
                return Ok(Some(
                    key.as_ref()
                        .deserialize_be_u64(CHANGE_ID_POS)
                        .ok_or_else(|| {
                            Error::InternalError(format!(
                                "Failed to deserialize changelog key for [{}/{:?}]: [{:?}]",
                                account_id, collection, key
                            ))
                        })?,
                ));
            }
        }
        Ok(None)
    }

    pub fn get_changes(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
        query: Query,
    ) -> crate::Result<Option<Changes>> {
        let collection = collection.into();
        let mut changelog = Changes::default();
        let (is_inclusive, from_change_id, to_change_id) = match query {
            Query::All => (true, 0, 0),
            Query::Since(change_id) => (false, change_id, 0),
            Query::SinceInclusive(change_id) => (true, change_id, 0),
            Query::RangeInclusive(from_change_id, to_change_id) => {
                (true, from_change_id, to_change_id)
            }
        };
        let key = LogKey {
            account_id,
            collection,
            change_id: from_change_id,
        }
        .serialize();
        let prefix = &key[0..CHANGE_ID_POS];
        let mut is_first = true;

        for entry in self.db.iterator_cf(
            &self.db.cf_handle(CF_LOGS).unwrap(),
            IteratorMode::From(&key, Direction::Forward),
        ) {
            let (key, value) = entry?;
            if !key.starts_with(prefix) {
                break;
            }
            let change_id = key
                .as_ref()
                .deserialize_be_u64(CHANGE_ID_POS)
                .ok_or_else(|| {
                    Error::InternalError(format!(
                        "Failed to deserialize changelog key for [{}/{:?}]: [{:?}]",
                        account_id, collection, key
                    ))
                })?;

            if change_id > from_change_id || (is_inclusive && change_id == from_change_id) {
                if to_change_id > 0 && change_id > to_change_id {
                    break;
                }
                if is_first {
                    changelog.from_change_id = change_id;
                    is_first = false;
                }
                changelog.to_change_id = change_id;
                changelog.deserialize(&value).ok_or_else(|| {
                    Error::InternalError(format!(
                        "Failed to deserialize changelog for [{}/{:?}]: [{:?}]",
                        account_id, collection, query
                    ))
                })?;
            }
        }

        if is_first {
            changelog.from_change_id = from_change_id;
            changelog.to_change_id = if to_change_id > 0 {
                to_change_id
            } else {
                from_change_id
            };
        }

        Ok(Some(changelog))
    }
}
