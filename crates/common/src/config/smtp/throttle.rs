/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
            throttle_id,
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
    throttle_id: &str,
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
        id: throttle_id.to_string(),
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

pub(crate) fn parse_throttle_key(value: &str) -> Result<u16, String> {
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
