/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use ahash::AHashMap;
use directory::Directory;
use store::{write::purge::PurgeSchedule, BlobStore, FtsStore, LookupStore, Store};

use crate::manager::config::ConfigManager;

#[derive(Default, Clone)]
pub struct Storage {
    pub data: Store,
    pub blob: BlobStore,
    pub fts: FtsStore,
    pub lookup: LookupStore,
    pub directory: Arc<Directory>,
    pub directories: AHashMap<String, Arc<Directory>>,
    pub purge_schedules: Vec<PurgeSchedule>,
    pub config: ConfigManager,

    pub stores: AHashMap<String, Store>,
    pub blobs: AHashMap<String, BlobStore>,
    pub lookups: AHashMap<String, LookupStore>,
    pub ftss: AHashMap<String, FtsStore>,
}
