/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::config::Config;

#[derive(Debug, Clone, Default)]
pub struct DavConfig {
    pub max_request_size: usize,
}

impl DavConfig {
    pub fn parse(config: &mut Config) -> Self {
        DavConfig {
            max_request_size: config
                .property("dav.limits.request-size")
                .unwrap_or(25 * 1024 * 1024),
        }
    }
}
