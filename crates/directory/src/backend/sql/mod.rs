/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::Store;

pub mod config;
pub mod lookup;

pub struct SqlDirectory {
    sql_store: Store,
    mappings: SqlMappings,
    pub(crate) data_store: Store,
}

#[derive(Debug, Default)]
pub(crate) struct SqlMappings {
    query_name: String,
    query_members: String,
    query_emails: String,
    query_recipients: String,
    query_secrets: String,
    column_description: String,
    column_secret: String,
    column_email: String,
    column_quota: String,
    column_type: String,
}
