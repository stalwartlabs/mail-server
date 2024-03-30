/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use utils::config::{utils::AsKey, Config, Rate};

use crate::expr::{tokenizer::TokenMap, Expression};

use super::*;

pub fn parse_throttle(
    config: &mut Config,
    prefix: impl AsKey,
    token_map: &TokenMap,
    available_throttle_keys: u16,
) -> Vec<Throttle> {
    let prefix_ = prefix.as_key();
    let mut throttles = Vec::new();
    for throttle_id in config
        .sub_keys(prefix, "")
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
    {
        let throttle_id = throttle_id.as_str();
        if let Some(throttle) = parse_throttle_item(
            config,
            (&prefix_, throttle_id),
            token_map,
            available_throttle_keys,
        ) {
            throttles.push(throttle);
        }
    }

    throttles
}

fn parse_throttle_item(
    config: &mut Config,
    prefix: impl AsKey,
    token_map: &TokenMap,
    available_throttle_keys: u16,
) -> Option<Throttle> {
    let prefix = prefix.as_key();

    // Skip disabled throttles
    if !config
        .property::<bool>((prefix.as_str(), "enable"))
        .unwrap_or(true)
    {
        return None;
    }

    let mut keys = 0;
    for (key_, value) in config
        .values((&prefix, "key"))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<Vec<_>>()
    {
        match parse_throttle_key(&value) {
            Ok(key) => {
                if (key & available_throttle_keys) != 0 {
                    keys |= key;
                } else {
                    let err = format!("Throttle key {value:?} is not available in this context");
                    config.new_build_error(key_, err);
                }
            }
            Err(err) => {
                config.new_parse_error(key_, err);
            }
        }
    }

    let throttle = Throttle {
        expr: Expression::try_parse(config, (prefix.as_str(), "match"), token_map)
            .unwrap_or_default(),
        keys,
        concurrency: config
            .property::<Option<u64>>((prefix.as_str(), "concurrency"))
            .filter(|&v| v.as_ref().map_or(false, |v| *v > 0))
            .unwrap_or_default(),
        rate: config
            .property::<Option<Rate>>((prefix.as_str(), "rate"))
            .filter(|v| v.as_ref().map_or(false, |r| r.requests > 0))
            .unwrap_or_default(),
    };

    // Validate
    if throttle.rate.is_none() && throttle.concurrency.is_none() {
        config.new_parse_error(
            prefix.as_str(),
            concat!(
                "Throttle needs to define a ",
                "valid 'rate' and/or 'concurrency' property."
            )
            .to_string(),
        );
        None
    } else {
        Some(throttle)
    }
}

pub(crate) fn parse_throttle_key(value: &str) -> utils::config::Result<u16> {
    match value {
        "rcpt" => Ok(THROTTLE_RCPT),
        "rcpt_domain" => Ok(THROTTLE_RCPT_DOMAIN),
        "sender" => Ok(THROTTLE_SENDER),
        "sender_domain" => Ok(THROTTLE_SENDER_DOMAIN),
        "authenticated_as" => Ok(THROTTLE_AUTH_AS),
        "listener" => Ok(THROTTLE_LISTENER),
        "mx" => Ok(THROTTLE_MX),
        "remote_ip" => Ok(THROTTLE_REMOTE_IP),
        "local_ip" => Ok(THROTTLE_LOCAL_IP),
        "helo_domain" => Ok(THROTTLE_HELO_DOMAIN),
        _ => Err(format!("Invalid throttle key {value:?}")),
    }
}
