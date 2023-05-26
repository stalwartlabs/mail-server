use foundationdb::{
    options::{self, MutationType},
    FdbError, KeySelector, RangeOption,
};
use futures::StreamExt;

use crate::{
    write::key::KeySerializer, Store, SUBSPACE_BITMAPS, SUBSPACE_INDEXES, SUBSPACE_LOGS,
    SUBSPACE_VALUES,
};

use super::bitmap::DenseBitmap;

const MAX_COMMIT_ATTEMPTS: u8 = 25;

impl Store {
    pub async fn purge_bitmaps(&self) -> crate::Result<()> {
        // Obtain all empty bitmaps
        let trx = self.db.create_trx()?;
        let mut iter = trx.get_ranges(
            RangeOption {
                begin: KeySelector::first_greater_or_equal(&[SUBSPACE_BITMAPS, 0u8][..]),
                end: KeySelector::first_greater_or_equal(&[SUBSPACE_BITMAPS, u8::MAX][..]),
                mode: options::StreamingMode::WantAll,
                reverse: false,
                ..Default::default()
            },
            true,
        );
        let mut delete_keys = Vec::new();

        while let Some(values) = iter.next().await {
            for value in values? {
                if value.value().iter().all(|byte| *byte == 0) {
                    delete_keys.push(value.key().to_vec());
                }
            }
        }
        if delete_keys.is_empty() {
            return Ok(());
        }

        // Delete keys
        let bitmap = DenseBitmap::empty();
        for chunk in delete_keys.chunks(1024) {
            let mut retry_count = 0;
            loop {
                let trx = self.db.create_trx()?;
                for key in chunk {
                    trx.atomic_op(key, &bitmap.bitmap, MutationType::CompareAndClear);
                }
                match trx.commit().await {
                    Ok(_) => {
                        break;
                    }
                    Err(err) => {
                        if retry_count < MAX_COMMIT_ATTEMPTS {
                            err.on_error().await?;
                            retry_count += 1;
                        } else {
                            return Err(FdbError::from(err).into());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn purge_account(&self, account_id: u32) -> crate::Result<()> {
        for subspace in [
            SUBSPACE_BITMAPS,
            SUBSPACE_VALUES,
            SUBSPACE_LOGS,
            SUBSPACE_INDEXES,
        ] {
            let from_key = KeySerializer::new(std::mem::size_of::<u32>() + 2)
                .write(subspace)
                .write(account_id)
                .write(0u8)
                .finalize();
            let to_key = KeySerializer::new(std::mem::size_of::<u32>() + 2)
                .write(subspace)
                .write(account_id)
                .write(u8::MAX)
                .finalize();

            let trx = self.db.create_trx()?;
            trx.clear_range(&from_key, &to_key);
            if let Err(err) = trx.commit().await {
                return Err(FdbError::from(err).into());
            }
        }

        Ok(())
    }
}
