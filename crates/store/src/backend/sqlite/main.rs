use std::sync::Arc;

use lru_cache::LruCache;
use parking_lot::Mutex;
use r2d2::Pool;
use tokio::sync::oneshot;
use utils::{config::Config, UnwrapFailure};

use crate::{
    blob::BlobStore, Store, SUBSPACE_ACLS, SUBSPACE_BITMAPS, SUBSPACE_BLOBS, SUBSPACE_INDEXES,
    SUBSPACE_LOGS, SUBSPACE_VALUES,
};

use super::pool::SqliteConnectionManager;

impl Store {
    // TODO configure rayon thread pool
    // TODO configure r2d2 pool
    // TODO configure id assigner size
    pub async fn open(config: &Config) -> crate::Result<Self> {
        let db = Self {
            conn_pool: Pool::new(
                SqliteConnectionManager::file(
                    config
                        .value_require("store.db.path")
                        .failed("Invalid configuration file"),
                )
                .with_init(|c| {
                    c.execute_batch(concat!(
                        "PRAGMA journal_mode = WAL; ",
                        "PRAGMA synchronous = normal; ",
                        "PRAGMA temp_store = memory;"
                    ))
                }),
            )?,
            worker_pool: rayon::ThreadPoolBuilder::new().build().map_err(|err| {
                crate::Error::InternalError(format!("Failed to build worker pool: {}", err))
            })?,
            id_assigner: Arc::new(Mutex::new(LruCache::new(1000))),
            blob: BlobStore::new(config).await?,
        };
        db.create_tables()?;
        Ok(db)
    }

    pub(super) fn create_tables(&self) -> crate::Result<()> {
        let conn = self.conn_pool.get()?;

        for table in [
            SUBSPACE_VALUES,
            SUBSPACE_LOGS,
            SUBSPACE_BLOBS,
            SUBSPACE_ACLS,
        ] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BLOB PRIMARY KEY,
                        v BLOB NOT NULL
                    )"
                ),
                [],
            )?;
        }

        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS {} (
                    k BLOB PRIMARY KEY
                )",
                char::from(SUBSPACE_INDEXES)
            ),
            [],
        )?;

        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS {} (
                    z BLOB PRIMARY KEY,
                    a INTEGER NOT NULL DEFAULT 0,
                    b INTEGER NOT NULL DEFAULT 0,
                    c INTEGER NOT NULL DEFAULT 0,
                    d INTEGER NOT NULL DEFAULT 0,
                    e INTEGER NOT NULL DEFAULT 0,
                    f INTEGER NOT NULL DEFAULT 0,
                    g INTEGER NOT NULL DEFAULT 0,
                    h INTEGER NOT NULL DEFAULT 0,
                    i INTEGER NOT NULL DEFAULT 0,
                    j INTEGER NOT NULL DEFAULT 0,
                    k INTEGER NOT NULL DEFAULT 0,
                    l INTEGER NOT NULL DEFAULT 0,
                    m INTEGER NOT NULL DEFAULT 0,
                    n INTEGER NOT NULL DEFAULT 0,
                    o INTEGER NOT NULL DEFAULT 0,
                    p INTEGER NOT NULL DEFAULT 0
                )",
                char::from(SUBSPACE_BITMAPS)
            ),
            [],
        )?;

        Ok(())
    }

    pub async fn spawn_worker<U, V>(&self, f: U) -> crate::Result<V>
    where
        U: FnOnce() -> crate::Result<V> + Send + 'static,
        V: Sync + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        self.worker_pool.spawn(move || {
            tx.send(f()).ok();
        });

        match rx.await {
            Ok(result) => result,
            Err(err) => Err(crate::Error::InternalError(format!(
                "Worker thread failed: {}",
                err
            ))),
        }
    }
}
