/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::{config::Config, glob::GlobSet};

#[derive(Debug, Clone, Default)]
pub struct SpamFilterConfig {
    pub list_dmarc_allow: GlobSet,
    pub list_spf_dkim_allow: GlobSet,
    pub list_freemail_providers: GlobSet,
    pub list_disposable_providers: GlobSet,
}

impl SpamFilterConfig {
    pub fn parse(config: &mut Config) -> Self {
        SpamFilterConfig::default()
    }
}
