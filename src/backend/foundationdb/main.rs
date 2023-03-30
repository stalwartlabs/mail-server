use foundationdb::Database;

use crate::Store;

impl Store {
    pub async fn open() -> crate::Result<Self> {
        Ok(Self {
            guard: unsafe { foundationdb::boot() },
            db: Database::default()?,
        })
    }
}

/*
impl Drop for Store {
    fn drop(&mut self) {
        self.guard.drop();
        self.db.drop();
    }
}
*/
