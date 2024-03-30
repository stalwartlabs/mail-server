use utils::config::Config;

use crate::{
    expr::{if_block::IfBlock, tokenizer::TokenMap},
    listener::blocked::BlockedIps,
    Network,
};

use super::CONNECTION_VARS;

impl Default for Network {
    fn default() -> Self {
        Self {
            blocked_ips: Default::default(),
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
            ..Default::default()
        };
        let token_map = &TokenMap::default().with_variables(CONNECTION_VARS);

        for (value, key) in [(&mut network.url, "server.url")] {
            if let Some(if_block) = IfBlock::try_parse(config, key, token_map) {
                *value = if_block;
            }
        }

        network
    }
}
