/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use trc::{subscriber::SubscriberBuilder, Level};

pub(crate) fn spawn_stdout_tracer(builder: SubscriberBuilder, ansi: bool) {
    let mut tx = builder.register();
    tokio::spawn(async move {
        while let Some(events) = tx.recv().await {
            for event in events {
                eprintln!("{}", event);
            }
        }
    });
}
