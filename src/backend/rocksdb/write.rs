use std::time::Instant;

use roaring::RoaringBitmap;
use rocksdb::ErrorKind;

use crate::{
    write::{key::KeySerializer, Batch, Operation},
    AclKey, BitmapKey, BlobKey, Deserialize, Error, IndexKey, LogKey, Serialize, Store, ValueKey,
    BM_BLOOM, BM_DOCUMENT_IDS,
};

use super::{
    bitmap::{clear_bit, set_bit},
    CF_BITMAPS, CF_BLOBS, CF_INDEXES, CF_LOGS, CF_VALUES,
};

impl Store {
    pub fn write(&self, batch: Batch) -> crate::Result<()> {
        let cf_values = self.db.cf_handle(CF_VALUES).unwrap();
        let cf_bitmaps = self.db.cf_handle(CF_BITMAPS).unwrap();
        let cf_indexes = self.db.cf_handle(CF_INDEXES).unwrap();
        let cf_logs = self.db.cf_handle(CF_LOGS).unwrap();
        let cf_blobs = self.db.cf_handle(CF_BLOBS).unwrap();
        let start = Instant::now();

        loop {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let txn = self.db.transaction();
            let mut wb = txn.get_writebatch();

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
                        set,
                    } => {
                        if *document_id_ == u32::MAX {
                            let key = BitmapKey {
                                account_id,
                                collection,
                                family: BM_DOCUMENT_IDS,
                                field: u8::MAX,
                                key: b"",
                            }
                            .serialize();
                            let mut document_ids = if let Some(bytes) = txn
                                .get_pinned_for_update_cf(&cf_bitmaps, &key, true)
                                .map_err(|err| {
                                    Error::InternalError(format!("get_cf failed: {}", err))
                                })? {
                                RoaringBitmap::deserialize(&bytes).ok_or_else(|| {
                                    Error::InternalError(format!(
                                        "Failed to deserialize key: {:?}",
                                        key
                                    ))
                                })?
                            } else {
                                RoaringBitmap::new()
                            };
                            document_id = if let Some(max_id) = document_ids.max() {
                                let mask = if max_id < 20000 {
                                    RoaringBitmap::from_sorted_iter(0..max_id + 2).unwrap()
                                } else {
                                    RoaringBitmap::full()
                                };
                                document_ids ^= mask;
                                document_ids.min().unwrap()
                            } else {
                                0
                            };
                            wb.merge_cf(&cf_bitmaps, key, set_bit(document_id));
                        } else {
                            document_id = *document_id_;
                            if !*set {
                                wb.merge_cf(
                                    &cf_bitmaps,
                                    BitmapKey {
                                        account_id,
                                        collection,
                                        family: BM_DOCUMENT_IDS,
                                        field: u8::MAX,
                                        key: b"",
                                    }
                                    .serialize(),
                                    clear_bit(document_id),
                                );
                            }
                        }
                    }
                    Operation::Value { field, set } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            field: *field,
                        }
                        .serialize();
                        if let Some(value) = set {
                            wb.put_cf(&cf_values, key, value);
                        } else {
                            wb.delete_cf(&cf_values, key);
                        }
                    }
                    Operation::Index { field, key, set } => {
                        let key_ = IndexKey {
                            account_id,
                            collection,
                            document_id,
                            field: *field,
                            key,
                        }
                        .serialize();
                        if *set {
                            wb.put_cf(&cf_indexes, key_, []);
                        } else {
                            wb.delete_cf(&cf_indexes, key_);
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
                            key,
                        }
                        .serialize();
                        let value = if *set {
                            set_bit(document_id)
                        } else {
                            clear_bit(document_id)
                        };
                        wb.merge_cf(&cf_bitmaps, key, value);
                    }
                    Operation::Bloom { family, field, set } => {
                        let key = KeySerializer::new(std::mem::size_of::<ValueKey>())
                            .write_leb128(account_id)
                            .write(collection)
                            .write_leb128(document_id)
                            .write(u8::MAX)
                            .write(BM_BLOOM | *family)
                            .write(*field)
                            .finalize();
                        if let Some(value) = set {
                            wb.put_cf(&cf_values, key, value);
                        } else {
                            wb.delete_cf(&cf_values, key);
                        }
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
                            wb.put_cf(&cf_blobs, key, []);
                        } else {
                            wb.delete_cf(&cf_blobs, key);
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
                            wb.put_cf(&cf_values, key, value);
                        } else {
                            wb.delete_cf(&cf_values, key);
                        }
                    }
                    Operation::Log { change_id, changes } => {
                        let coco = "_";
                        let key = LogKey {
                            account_id,
                            collection,
                            change_id: *change_id,
                        }
                        .serialize();
                        wb.put_cf(&cf_logs, key, changes);
                    }
                }
            }

            match self.db.write(wb) {
                Ok(_) => {
                    //println!("Success with id {}", document_id);
                    return Ok(());
                }
                Err(err) => match err.kind() {
                    ErrorKind::Busy | ErrorKind::MergeInProgress | ErrorKind::TryAgain
                        if start.elapsed().as_secs() < 5 => {}
                    _ => return Err(err.into()),
                },
            }
        }
    }
}
