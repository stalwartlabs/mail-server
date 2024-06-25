/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::{AHashMap, AHashSet};
use store::Store;

use crate::Principal;

pub mod config;
pub mod lookup;

#[derive(Debug)]
pub struct MemoryDirectory {
    principals: Vec<Principal<u32>>,
    emails_to_ids: AHashMap<String, Vec<EmailType>>,
    pub(crate) data_store: Store,
    domains: AHashSet<String>,
}

#[derive(Debug)]
enum EmailType {
    Primary(u32),
    Alias(u32),
    List(u32),
}
