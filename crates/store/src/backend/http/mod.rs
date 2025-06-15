/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod config;
pub mod lookup;

use std::{
    sync::atomic::{AtomicBool, AtomicU64},
    time::Duration,
};

use ahash::AHashMap;
use arc_swap::ArcSwap;

use crate::Value;

#[derive(Debug, Clone)]
pub struct HttpStoreConfig {
    pub id: String,
    pub url: String,
    pub retry: u64,
    pub refresh: u64,
    pub timeout: Duration,
    pub gzipped: bool,
    pub max_size: usize,
    pub max_entries: usize,
    pub max_entry_size: usize,
    pub format: HttpStoreFormat,
}

#[derive(Debug, Clone)]
pub enum HttpStoreFormat {
    List,
    Csv {
        index_key: u32,
        index_value: Option<u32>,
        separator: char,
        skip_first: bool,
    },
}

#[derive(Debug)]
pub struct HttpStore {
    pub entries: ArcSwap<AHashMap<String, Value<'static>>>,
    pub expires: AtomicU64,
    pub in_flight: AtomicBool,
    pub config: HttpStoreConfig,
}
