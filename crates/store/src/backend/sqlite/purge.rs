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
    write::key::KeySerializer, SUBSPACE_BITMAPS, SUBSPACE_INDEXES, SUBSPACE_LOGS, SUBSPACE_VALUES,
    U32_LEN,
};

use super::SqliteStore;

impl SqliteStore {
    pub(crate) async fn purge_bitmaps(&self) -> crate::Result<()> {
        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            //Todo
            conn.prepare_cached(concat!(
                "DELETE FROM b WHERE ",
                "a = 0 AND ",
                "b = 0 AND ",
                "c = 0 AND ",
                "d = 0 AND ",
                "e = 0 AND ",
                "f = 0 AND ",
                "g = 0 AND ",
                "h = 0 AND ",
                "i = 0 AND ",
                "j = 0 AND ",
                "k = 0 AND ",
                "l = 0 AND ",
                "m = 0 AND ",
                "n = 0 AND ",
                "o = 0 AND ",
                "p = 0"
            ))?
            .execute([])?;

            Ok(())
        })
        .await
    }

    pub(crate) async fn purge_account(&self, account_id: u32) -> crate::Result<()> {
        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            let from_key = KeySerializer::new(U32_LEN).write(account_id).finalize();
            let to_key = KeySerializer::new(U32_LEN).write(account_id + 1).finalize();

            for (table, i) in [
                (SUBSPACE_BITMAPS, 'z'),
                (SUBSPACE_VALUES, 'k'),
                (SUBSPACE_LOGS, 'k'),
                (SUBSPACE_INDEXES, 'k'),
            ] {
                conn.prepare_cached(&format!(
                    "DELETE FROM {} WHERE {} >= ? AND {} < ?",
                    char::from(table),
                    i,
                    i
                ))?
                .execute([&from_key, &to_key])?;
            }

            Ok(())
        })
        .await
    }
}
