/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use jmap_proto::types::collection::Collection;
use store::{
    SUBSPACE_BITMAP_ID, U64_LEN,
    write::{AnyKey, key::KeySerializer},
};
use trc::AddContext;

pub(crate) async fn migrate_threads(server: &Server, account_id: u32) -> trc::Result<u64> {
    // Obtain email ids
    let thread_ids = server
        .get_document_ids(account_id, Collection::Thread)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_threads = thread_ids.len();
    if num_threads == 0 {
        return Ok(0);
    }

    // Delete threads
    server
        .store()
        .delete_range(
            AnyKey {
                subspace: SUBSPACE_BITMAP_ID,
                key: KeySerializer::new(U64_LEN)
                    .write(account_id)
                    .write(u8::from(Collection::Thread))
                    .finalize(),
            },
            AnyKey {
                subspace: SUBSPACE_BITMAP_ID,
                key: KeySerializer::new(U64_LEN)
                    .write(account_id)
                    .write(u8::from(Collection::Thread))
                    .write(&[u8::MAX; 16][..])
                    .finalize(),
            },
        )
        .await
        .caused_by(trc::location!())?;

    // Increment document id counter
    server
        .store()
        .assign_document_ids(
            account_id,
            Collection::Thread,
            thread_ids.max().map(|id| id as u64).unwrap_or(num_threads) + 1,
        )
        .await
        .caused_by(trc::location!())?;

    Ok(num_threads)
}
