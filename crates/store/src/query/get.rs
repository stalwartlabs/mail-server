use crate::{Deserialize, Key, Store, ValueKey};

impl Store {
    pub async fn get_value<U>(&self, key: ValueKey) -> crate::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        #[cfg(feature = "is_async")]
        {
            self.read_transaction().await?.get_value(key).await
        }

        #[cfg(feature = "is_sync")]
        {
            let trx = self.read_transaction()?;
            self.spawn_worker(move || trx.get_value(key)).await
        }
    }

    pub async fn get_values<U>(&self, key: Vec<ValueKey>) -> crate::Result<Vec<Option<U>>>
    where
        U: Deserialize + 'static,
    {
        #[cfg(feature = "is_async")]
        {
            let mut trx = self.read_transaction().await?;
            let mut results = Vec::with_capacity(key.len());

            for key in key {
                trx.refresh_if_old().await?;
                results.push(trx.get_value(key).await?);
            }

            Ok(results)
        }

        #[cfg(feature = "is_sync")]
        {
            let trx = self.read_transaction()?;
            self.spawn_worker(move || {
                let mut results = Vec::with_capacity(key.len());
                for key in key {
                    results.push(trx.get_value(key)?);
                }

                Ok(results)
            })
            .await
        }
    }

    pub async fn get_last_change_id(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
    ) -> crate::Result<Option<u64>> {
        let collection = collection.into();

        #[cfg(feature = "is_async")]
        {
            self.read_transaction()
                .await?
                .get_last_change_id(account_id, collection)
                .await
        }

        #[cfg(feature = "is_sync")]
        {
            let trx = self.read_transaction()?;
            self.spawn_worker(move || trx.get_last_change_id(account_id, collection))
                .await
        }
    }

    pub async fn iterate<T: Sync + Send + 'static>(
        &self,
        acc: T,
        begin: impl Key,
        end: impl Key,
        first: bool,
        ascending: bool,
        cb: impl Fn(&mut T, &[u8], &[u8]) -> crate::Result<bool> + Sync + Send + 'static,
    ) -> crate::Result<T> {
        #[cfg(feature = "is_async")]
        {
            self.read_transaction()
                .await?
                .iterate(acc, begin, end, first, ascending, cb)
                .await
        }

        #[cfg(feature = "is_sync")]
        {
            let trx = self.read_transaction()?;
            self.spawn_worker(move || trx.iterate(acc, begin, end, first, ascending, cb))
                .await
        }
    }
}
