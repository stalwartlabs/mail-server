/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::config::Config;

#[derive(Debug, Clone, Default)]
pub struct DavConfig {
    pub max_request_size: usize,
    pub dead_property_size: Option<usize>,
    pub live_property_size: usize,
    pub max_lock_timeout: u64,
    pub max_changes: usize,
}

impl DavConfig {
    pub fn parse(config: &mut Config) -> Self {
        DavConfig {
            max_request_size: config
                .property("dav.limits.size.request")
                .unwrap_or(25 * 1024 * 1024),
            dead_property_size: config
                .property_or_default::<Option<usize>>("dav.limits.size.dead-property", "1024")
                .unwrap_or(Some(1024)),
            live_property_size: config
                .property("dav.limits.size.live-property")
                .unwrap_or(250),
            max_lock_timeout: config.property("dav.limits.timeout.max-lock").unwrap_or(60),
            max_changes: config.property("dav.limits.max-changes").unwrap_or(1000),
        }
    }
}
