use utils::codec::leb128::Leb128Iterator;

use crate::{
    write::{now, BatchBuilder, F_CLEAR},
    BlobKey, Deserialize, Store, BLOB_HASH_LEN,
};

struct BlobPurge {
    batch: BatchBuilder,
    id: [u8; BLOB_HASH_LEN],
    link_count: u32,
    delete: Vec<[u8; BLOB_HASH_LEN]>,
}

impl Store {
    pub async fn purge_blobs(&self, ttl: u64) -> crate::Result<()> {
        let now = now();

        let results = BlobPurge {
            batch: BatchBuilder::new(),
            id: [0u8; BLOB_HASH_LEN],
            link_count: u32::MAX,
            delete: vec![],
        };

        let from_key = BlobKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            hash: [0; BLOB_HASH_LEN],
        };
        let to_key = BlobKey {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            hash: [u8::MAX; BLOB_HASH_LEN],
        };

        let mut results = self
            .iterate(results, from_key, to_key, false, true, move |b, k, v| {
                if !k.starts_with(&b.id) {
                    if b.link_count == 0 {
                        b.delete.push(b.id);
                    }
                    b.link_count = 0;
                    b.id.copy_from_slice(&k[..BLOB_HASH_LEN]);
                }

                if !v.is_empty() {
                    let timestamp = u64::deserialize(v)?;

                    if (now >= timestamp && now - timestamp >= ttl)
                        || (now < timestamp && timestamp - now >= ttl)
                    {
                        let mut iter = k[BLOB_HASH_LEN..].iter();
                        if let (Some(account_id), Some(collection), Some(document_id)) =
                            (iter.next_leb128(), iter.next(), iter.next_leb128())
                        {
                            b.batch
                                .with_account_id(account_id)
                                .with_collection(*collection)
                                .update_document(document_id)
                                .blob(b.id.to_vec(), F_CLEAR);
                        }
                    } else {
                        b.link_count += 1;
                    }
                } else {
                    b.link_count += 1;
                }

                Ok(true)
            })
            .await?;

        if results.link_count == 0 {
            results.delete.push(results.id);
        }

        if !results.batch.is_empty() {
            self.write(results.batch.build()).await?;
        }

        for hash in results.delete {
            self.blob.delete(&crate::BlobId { hash }).await?;
        }

        Ok(())
    }
}
