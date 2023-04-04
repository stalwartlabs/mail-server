use foundationdb::Database;

use crate::Store;

impl Store {
    pub async fn open(config: &Config) -> crate::Result<Self> {
        Ok(Self {
            guard: unsafe { foundationdb::boot() },
            db: Database::default()?,
            blob: BlobStore::new(config).await?,
        })
    }
}
