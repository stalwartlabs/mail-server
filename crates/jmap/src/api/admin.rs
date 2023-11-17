/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
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

use jmap_proto::types::collection::Collection;
use store::{write::BatchBuilder, Serialize};

use crate::{NamedKey, JMAP};

impl JMAP {
    pub async fn delete_account(&self, account_name: &str, account_id: u32) -> store::Result<()> {
        let test = true;

        // Unlink all account's blobs
        self.store.blob_hash_unlink_account(account_id).await?;

        // Revoke ACLs
        self.store.acl_revoke_all(account_id).await?;

        // Delete account data
        self.store.purge_account(account_id).await?;

        // Remove FTS index
        let todo = 1;

        // Delete account
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(u32::MAX)
            .with_collection(Collection::Principal)
            .clear(NamedKey::Name(account_name))
            .clear(NamedKey::Id::<&[u8]>(account_id))
            .clear(NamedKey::Quota::<&[u8]>(account_id));

        self.store.write(batch.build()).await?;

        Ok(())
    }

    pub async fn rename_account(
        &self,
        new_account_name: &str,
        account_name: &str,
        account_id: u32,
    ) -> store::Result<()> {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(u32::MAX)
            .with_collection(Collection::Principal)
            .clear(NamedKey::Name(account_name))
            .set(
                NamedKey::Id::<&[u8]>(account_id),
                new_account_name.serialize(),
            )
            .set(NamedKey::Name(new_account_name), account_id.serialize());
        self.store.write(batch.build()).await?;
        Ok(())
    }
}
