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

use super::*;

pub(crate) const HTTP_VARS: &[u32; 11] = &[
    V_LISTENER,
    V_REMOTE_IP,
    V_REMOTE_PORT,
    V_LOCAL_IP,
    V_LOCAL_PORT,
    V_PROTOCOL,
    V_TLS,
    V_URL,
    V_URL_PATH,
    V_HEADERS,
    V_METHOD,
];

impl Default for Network {
    fn default() -> Self {
        Self {
            blocked_ips: Default::default(),
            allowed_ips: Default::default(),
            http_response_url: IfBlock::new::<()>(
                "server.http.url",
                [],
                "protocol + '://' + key_get('default', 'hostname') + ':' + local_port",
            ),
            http_allowed_endpoint: IfBlock::new::<()>("server.http.allowed-endpoint", [], "200"),
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
        let token_map = &TokenMap::default().with_variables(HTTP_VARS);

        for (value, key) in [
            (&mut network.http_response_url, "server.http.url"),
            (
                &mut network.http_allowed_endpoint,
                "server.http.allowed-endpoint",
            ),
        ] {
            if let Some(if_block) = IfBlock::try_parse(config, key, token_map) {
                *value = if_block;
            }
        }

        network
    }
}
