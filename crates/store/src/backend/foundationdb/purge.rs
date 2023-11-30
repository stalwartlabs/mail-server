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

use foundationdb::{
    options::{self, MutationType},
    FdbError, KeySelector, RangeOption,
};
use futures::StreamExt;

use crate::{
    write::{bitmap::DenseBitmap, key::KeySerializer},
    SUBSPACE_BITMAPS, SUBSPACE_INDEXES, SUBSPACE_INDEX_VALUES, SUBSPACE_LOGS, SUBSPACE_VALUES,
    U32_LEN,
};

use super::FdbStore;

const MAX_COMMIT_ATTEMPTS: u8 = 25;

impl FdbStore {
    pub(crate) async fn purge_bitmaps(&self) -> crate::Result<()> {
        // Obtain all empty bitmaps
        let trx = self.db.create_trx()?;
        let mut iter = trx.get_ranges(
            RangeOption {
                begin: KeySelector::first_greater_or_equal(&[SUBSPACE_BITMAPS, 0u8][..]),
                end: KeySelector::first_greater_or_equal(&[SUBSPACE_BITMAPS, u8::MAX][..]),
                mode: options::StreamingMode::WantAll,
                reverse: false,
                ..Default::default()
            },
            true,
        );
        let mut delete_keys = Vec::new();

        while let Some(values) = iter.next().await {
            for value in values? {
                if value.value().iter().all(|byte| *byte == 0) {
                    delete_keys.push(value.key().to_vec());
                }
            }
        }
        if delete_keys.is_empty() {
            return Ok(());
        }

        // Delete keys
        let bitmap = DenseBitmap::empty();
        for chunk in delete_keys.chunks(1024) {
            let mut retry_count = 0;
            loop {
                let trx = self.db.create_trx()?;
                for key in chunk {
                    trx.atomic_op(key, &bitmap.bitmap, MutationType::CompareAndClear);
                }
                match trx.commit().await {
                    Ok(_) => {
                        break;
                    }
                    Err(err) => {
                        if retry_count < MAX_COMMIT_ATTEMPTS {
                            err.on_error().await?;
                            retry_count += 1;
                        } else {
                            return Err(FdbError::from(err).into());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn purge_account(&self, account_id: u32) -> crate::Result<()> {
        for subspace in [
            SUBSPACE_BITMAPS,
            SUBSPACE_VALUES,
            SUBSPACE_LOGS,
            SUBSPACE_INDEXES,
            SUBSPACE_INDEX_VALUES,
        ] {
            let from_key = KeySerializer::new(U32_LEN + 2)
                .write(subspace)
                .write(account_id)
                .write(0u8)
                .finalize();
            let to_key = KeySerializer::new(U32_LEN + 2)
                .write(subspace)
                .write(account_id)
                .write(u8::MAX)
                .finalize();

            let trx = self.db.create_trx()?;
            trx.clear_range(&from_key, &to_key);
            if let Err(err) = trx.commit().await {
                return Err(FdbError::from(err).into());
            }
        }

        Ok(())
    }
}
