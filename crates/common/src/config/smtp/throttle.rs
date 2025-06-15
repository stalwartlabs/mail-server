/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::config::{Config, Rate, utils::AsKey};

use crate::expr::{Expression, tokenizer::TokenMap};

use super::*;

pub fn parse_queue_rate_limiter(
    config: &mut Config,
    prefix: impl AsKey,
    token_map: &TokenMap,
    available_rate_limiter_keys: u16,
) -> Vec<QueueRateLimiter> {
    let prefix_ = prefix.as_key();
    let mut rate_limiters = Vec::new();
    for rate_limiter_id in config
        .sub_keys(prefix, "")
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
    {
        let rate_limiter_id = rate_limiter_id.as_str();
        if let Some(rate_limiter) = parse_queue_rate_limiter_item(
            config,
            (&prefix_, rate_limiter_id),
            rate_limiter_id,
            token_map,
            available_rate_limiter_keys,
        ) {
            rate_limiters.push(rate_limiter);
        }
    }

    rate_limiters
}

fn parse_queue_rate_limiter_item(
    config: &mut Config,
    prefix: impl AsKey,
    rate_limiter_id: &str,
    token_map: &TokenMap,
    available_rate_limiter_keys: u16,
) -> Option<QueueRateLimiter> {
    let prefix = prefix.as_key();

    // Skip disabled rate_limiters
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
        match parse_queue_rate_limiter_key(&value) {
            Ok(key) => {
                if (key & available_rate_limiter_keys) != 0 {
                    keys |= key;
                } else {
                    let err =
                        format!("Rate limiter key {value:?} is not available in this context");
                    config.new_build_error(key_, err);
                }
            }
            Err(err) => {
                config.new_parse_error(key_, err);
            }
        }
    }

    Some(QueueRateLimiter {
        id: rate_limiter_id.to_string(),
        expr: Expression::try_parse(config, (prefix.as_str(), "match"), token_map)
            .unwrap_or_default(),
        keys,
        rate: config
            .property_require::<Rate>((prefix.as_str(), "rate"))
            .filter(|r| r.requests > 0)?,
    })
}

pub(crate) fn parse_queue_rate_limiter_key(value: &str) -> Result<u16, String> {
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
        _ => Err(format!("Invalid THROTTLE key {value:?}")),
    }
}
