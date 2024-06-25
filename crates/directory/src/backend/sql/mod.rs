/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::{LookupStore, Store};

pub mod config;
pub mod lookup;

pub struct SqlDirectory {
    store: LookupStore,
    mappings: SqlMappings,
    pub(crate) data_store: Store,
}

#[derive(Debug, Default)]
pub(crate) struct SqlMappings {
    query_name: String,
    query_members: String,
    query_recipients: String,
    query_emails: String,
    query_domains: String,
    query_verify: String,
    query_expand: String,
    column_description: String,
    column_secret: String,
    column_quota: String,
    column_type: String,
}
