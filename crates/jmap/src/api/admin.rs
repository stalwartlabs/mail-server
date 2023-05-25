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
