use utils::config::Config;

use crate::{
    expr::{if_block::IfBlock, tokenizer::TokenMap},
    listener::blocked::BlockedIps,
    Network,
};

use super::smtp::*;

impl Default for Network {
    fn default() -> Self {
        Self {
            blocked_ips: Default::default(),
            hostname: IfBlock::new("localhost".to_string()),
            url: IfBlock::new("http://localhost:8080".to_string()),
        }
    }
}

impl Network {
    pub fn parse(config: &mut Config) -> Self {
        let mut network = Network {
            blocked_ips: BlockedIps::parse(config),
            ..Default::default()
        };
        let token_map = &TokenMap::default().with_smtp_variables(&[
            V_LISTENER,
            V_REMOTE_IP,
            V_LOCAL_IP,
            V_HELO_DOMAIN,
        ]);

        for (value, key) in [
            (&mut network.hostname, "server.hostname"),
            (&mut network.url, "server.url"),
        ] {
            if let Some(if_block) = IfBlock::try_parse(config, key, token_map) {
                *value = if_block;
            }
        }

        network
    }
}
