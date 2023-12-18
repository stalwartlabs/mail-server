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

use std::time::Duration;

use foundationdb::{options::DatabaseOption, Database};
use utils::config::{utils::AsKey, Config};

use super::FdbStore;

impl FdbStore {
    pub async fn open(config: &Config, prefix: impl AsKey) -> crate::Result<Self> {
        let prefix = prefix.as_key();
        let guard = unsafe { foundationdb::boot() };

        let db = Database::new(config.value((&prefix, "path")))?;
        if let Some(value) = config.property::<Duration>((&prefix, "transaction.timeout"))? {
            db.set_option(DatabaseOption::TransactionTimeout(value.as_millis() as i32))?;
        }
        if let Some(value) = config.property((&prefix, "transaction.retry-limit"))? {
            db.set_option(DatabaseOption::TransactionRetryLimit(value))?;
        }
        if let Some(value) =
            config.property::<Duration>((&prefix, "transaction.max-retry-delay"))?
        {
            db.set_option(DatabaseOption::TransactionMaxRetryDelay(
                value.as_millis() as i32
            ))?;
        }
        if let Some(value) = config.property((&prefix, "transaction.machine-id"))? {
            db.set_option(DatabaseOption::MachineId(value))?;
        }
        if let Some(value) = config.property((&prefix, "transaction.datacenter-id"))? {
            db.set_option(DatabaseOption::DatacenterId(value))?;
        }

        Ok(Self { guard, db })
    }
}
