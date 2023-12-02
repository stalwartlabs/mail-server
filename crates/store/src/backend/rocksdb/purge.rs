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

use crate::{write::key::KeySerializer, U32_LEN};

use super::{RocksDbStore, CF_BITMAPS, CF_INDEXES, CF_LOGS, CF_VALUES};

impl RocksDbStore {
    pub(crate) async fn purge_bitmaps(&self) -> crate::Result<()> {
        Ok(())
    }

    pub(crate) async fn purge_account(&self, account_id: u32) -> crate::Result<()> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            let key = KeySerializer::new(U32_LEN).write(account_id).finalize();

            // TODO use delete_range when implemented (see https://github.com/rust-rocksdb/rust-rocksdb/issues/839)
            for cf_name in [CF_BITMAPS, CF_VALUES, CF_LOGS, CF_INDEXES] {
                let mut delete_keys = Vec::new();
                let it_mode = IteratorMode::From(&key, Direction::Forward);
                let cf = db.cf_handle(cf_name).unwrap();

                for row in db.iterator_cf(&cf, it_mode) {
                    let (k, _) = row?;
                    if !k.starts_with(&key) {
                        break;
                    }
                    delete_keys.push(k);
                }

                for k in delete_keys {
                    db.delete_cf(&cf, &k)?;
                }
            }

            Ok(())
        })
        .await
    }
}
