/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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
    write::{assert::HashedValue, BatchBuilder},
    BitmapKey, ValueKey,
};

use crate::{mailbox::set::SCHEMA, JMAP};

impl JMAP {
    pub async fn delete_account(&self, account_id: u32) -> store::Result<()> {
        // Delete blobs
        self.store
            .bulk_delete_blob(&store::BlobKind::Linked {
                account_id,
                collection: Collection::Email.into(),
                document_id: 0,
            })
            .await?;

        // Delete mailboxes
        let mut batch = BatchBuilder::new();
        batch
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
                .get_value::<HashedValue<Object<Value>>>(ValueKey::new(
                    account_id,
                    Collection::Mailbox,
                    mailbox_id,
                    Property::Value,
                ))
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
}
