use crate::{Deserialize, Store, ValueKey};

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
}
