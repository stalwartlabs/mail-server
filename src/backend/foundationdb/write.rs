use std::time::Instant;

use foundationdb::{options::MutationType, FdbError};

use crate::{
    write::{Batch, Operation},
    AclKey, BitmapKey, BlobKey, IndexKey, LogKey, Serialize, Store, ValueKey,
};

use super::bitmap::DenseBitmap;

impl Store {
    pub async fn write(&self, batch: Batch) -> crate::Result<()> {
        let start = Instant::now();
        let mut or_bitmap = DenseBitmap::empty();
        let mut and_bitmap = DenseBitmap::full();
        let mut block_num = u32::MAX;
        let mut retry_count = 0;

        loop {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let trx = self.db.create_trx()?;

            for op in &batch.ops {
                match op {
                    Operation::AccountId {
                        account_id: account_id_,
                    } => {
                        account_id = *account_id_;
                    }
                    Operation::Collection {
                        collection: collection_,
                    } => {
                        collection = *collection_;
                    }
                    Operation::DocumentId {
                        document_id: document_id_,
                    } => {
                        if block_num != u32::MAX {
                            or_bitmap.reset();
                            and_bitmap.reset();
                        }
                        document_id = *document_id_;
                        or_bitmap.set(document_id);
                        and_bitmap.clear(document_id);
                        block_num = or_bitmap.block_num;
                    }
                    Operation::Value { family, field, set } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            family: *family,
                            field: *field,
                        }
                        .serialize();
                        if let Some(value) = set {
                            trx.set(&key, value);
                        } else {
                            trx.clear(&key);
                        }
                    }
                    Operation::Index { field, key, set } => {
                        let key = IndexKey {
                            account_id,
                            collection,
                            document_id,
                            field: *field,
                            key,
                        }
                        .serialize();
                        if *set {
                            trx.set(&key, &[]);
                        } else {
                            trx.clear(&key);
                        }
                    }
                    Operation::Bitmap {
                        family,
                        field,
                        key,
                        set,
                    } => {
                        let key = BitmapKey {
                            account_id,
                            collection,
                            family: *family,
                            field: *field,
                            block_num,
                            key,
                        }
                        .serialize();
                        if *set {
                            trx.atomic_op(&key, &or_bitmap.bitmap, MutationType::BitOr);
                        } else {
                            trx.atomic_op(&key, &and_bitmap.bitmap, MutationType::BitAnd);
                        };
                    }
                    Operation::Blob { key, set } => {
                        let key = BlobKey {
                            account_id,
                            collection,
                            document_id,
                            hash: key,
                        }
                        .serialize();
                        if *set {
                            trx.set(&key, &[]);
                        } else {
                            trx.clear(&key);
                        }
                    }
                    Operation::Acl {
                        grant_account_id,
                        set,
                    } => {
                        let key = AclKey {
                            grant_account_id: *grant_account_id,
                            to_account_id: account_id,
                            to_collection: collection,
                            to_document_id: document_id,
                        }
                        .serialize();
                        if let Some(value) = set {
                            trx.set(&key, value);
                        } else {
                            trx.clear(&key);
                        }
                    }
                    Operation::Log {
                        collection,
                        change_id,
                        set,
                    } => {
                        let key = LogKey {
                            account_id,
                            collection: *collection,
                            change_id: *change_id,
                        }
                        .serialize();
                        trx.set(&key, set);
                    }
                }
            }

            match trx.commit().await {
                Ok(_) => {
                    //println!("Success with id {} block {block_num}", document_id);
                    return Ok(());
                }
                Err(err) => {
                    if retry_count < 10 && start.elapsed().as_secs() < 5 {
                        println!("Retrying with id {}", document_id);
                        err.on_error().await?;
                        retry_count += 1;
                    } else {
                        println!("Error with id {}", document_id);
                        return Err(FdbError::from(err).into());
                    }
                }
            }
        }
    }
}
