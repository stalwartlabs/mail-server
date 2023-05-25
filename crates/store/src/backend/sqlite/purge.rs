use crate::{
    write::key::KeySerializer, Store, SUBSPACE_BITMAPS, SUBSPACE_INDEXES, SUBSPACE_LOGS,
    SUBSPACE_VALUES,
};

impl Store {
    pub async fn purge_bitmaps(&self) -> crate::Result<()> {
        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            //Todo
            conn.prepare_cached(concat!(
                "DELETE FROM b WHERE ",
                "a = 0 AND ",
                "b = 0 AND ",
                "c = 0 AND ",
                "d = 0 AND ",
                "e = 0 AND ",
                "f = 0 AND ",
                "g = 0 AND ",
                "h = 0 AND ",
                "i = 0 AND ",
                "j = 0 AND ",
                "k = 0 AND ",
                "l = 0 AND ",
                "m = 0 AND ",
                "n = 0 AND ",
                "o = 0 AND ",
                "p = 0"
            ))?
            .execute([])?;

            Ok(())
        })
        .await
    }

    pub async fn purge_account(&self, account_id: u32) -> crate::Result<()> {
        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            let from_key = KeySerializer::new(std::mem::size_of::<u32>())
                .write(account_id)
                .finalize();
            let to_key = KeySerializer::new(std::mem::size_of::<u32>())
                .write(account_id + 1)
                .finalize();

            for (table, i) in [
                (SUBSPACE_BITMAPS, 'z'),
                (SUBSPACE_VALUES, 'k'),
                (SUBSPACE_LOGS, 'k'),
                (SUBSPACE_INDEXES, 'k'),
            ] {
                conn.prepare_cached(&format!(
                    "DELETE FROM {} WHERE {} >= ? AND {} < ?",
                    char::from(table),
                    i,
                    i
                ))?
                .execute([&from_key, &to_key])?;
            }

            Ok(())
        })
        .await
    }
}
