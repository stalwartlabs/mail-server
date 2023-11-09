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

use jmap_proto::{
    object::{index::ObjectIndexBuilder, Object},
    types::{collection::Collection, property::Property, value::Value},
};
use store::{
    write::{assert::HashedValue, BatchBuilder, ValueClass},
    BitmapKey, Serialize, StorePurge, StoreRead, StoreWrite, ValueKey,
};

use crate::{mailbox::set::SCHEMA, NamedKey, JMAP};

impl JMAP {
    pub async fn delete_account(&self, account_name: &str, account_id: u32) -> store::Result<()> {
        // Delete blobs
        self.store.delete_account_blobs(account_id).await?;

        // Delete mailboxes
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(u32::MAX)
            .with_collection(Collection::Principal)
            .clear(NamedKey::Name(account_name))
            .clear(NamedKey::Id::<&[u8]>(account_id))
            .clear(NamedKey::Quota::<&[u8]>(account_id))
            .with_account_id(account_id)
            .with_collection(Collection::Mailbox);
        for mailbox_id in self
            .store
            .get_bitmap(BitmapKey::document_ids(account_id, Collection::Mailbox))
            .await?
            .unwrap_or_default()
        {
            let mailbox = self
                .store
                .get_value::<HashedValue<Object<Value>>>(ValueKey {
                    account_id,
                    collection: Collection::Mailbox.into(),
                    document_id: mailbox_id,
                    class: ValueClass::Property(Property::Value.into()),
                })
                .await?
                .ok_or_else(|| {
                    store::Error::InternalError(format!("Mailbox {} not found", mailbox_id))
                })?;
            batch
                .delete_document(mailbox_id)
                .custom(ObjectIndexBuilder::new(SCHEMA).with_current(mailbox));
        }
        if !batch.is_empty() {
            self.store.write(batch.build()).await?;
        }

        // Delete account
        self.store.purge_account(account_id).await?;

        Ok(())
    }

    pub async fn rename_account(
        &self,
        new_account_name: &str,
        account_name: &str,
        account_id: u32,
    ) -> store::Result<()> {
        // Delete blobs
        self.store.delete_account_blobs(account_id).await?;

        // Delete mailboxes
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
