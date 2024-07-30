/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    expr::{if_block::IfBlock, tokenizer::TokenMap},
    listener::blocked::{AllowedIps, BlockedIps},
    Network,
};
use utils::config::Config;

use super::CONNECTION_VARS;

impl Default for Network {
    fn default() -> Self {
        Self {
            blocked_ips: Default::default(),
            allowed_ips: Default::default(),
            url: IfBlock::new::<()>(
                "server.http.url",
                [],
                "protocol + '://' + key_get('default', 'hostname') + ':' + local_port",
            ),
        }
    }
}

impl Network {
    pub fn parse(config: &mut Config) -> Self {
        let mut network = Network {
            blocked_ips: BlockedIps::parse(config),
            allowed_ips: AllowedIps::parse(config),
            ..Default::default()
        };
        let token_map = &TokenMap::default().with_variables(CONNECTION_VARS);

        for (value, key) in [(&mut network.url, "server.http.url")] {
            if let Some(if_block) = IfBlock::try_parse(config, key, token_map) {
                *value = if_block;
            }
        }

        network
    }
}
