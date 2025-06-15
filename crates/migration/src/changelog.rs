/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use store::{
    SUBSPACE_LOGS, U64_LEN,
    write::{AnyKey, key::KeySerializer},
};
use trc::AddContext;

pub(crate) async fn reset_changelog(server: &Server) -> trc::Result<()> {
    // Delete changes
    server
        .store()
        .delete_range(
            AnyKey {
                subspace: SUBSPACE_LOGS,
                key: KeySerializer::new(U64_LEN).write(0u8).finalize(),
            },
            AnyKey {
                subspace: SUBSPACE_LOGS,
                key: KeySerializer::new(U64_LEN)
                    .write(&[u8::MAX; 16][..])
                    .finalize(),
            },
        )
        .await
        .caused_by(trc::location!())
}
