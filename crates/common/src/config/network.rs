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

/*
impl Webhooks {
    pub fn parse(config: &mut Config) -> Self {
        let mut hooks = Webhooks {
            events: Default::default(),
            hooks: Default::default(),
        };

        for id in config
            .sub_keys("webhook", ".url")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        {
            if let Some(webhook) = parse_webhook(config, &id) {
                hooks.events.extend(&webhook.events);
                hooks.hooks.insert(webhook.id, webhook.into());
            }
        }

        hooks
    }
}

fn parse_webhook(config: &mut Config, id: &str) -> Option<Webhook> {
    let mut headers = HeaderMap::new();

    for (header, value) in config
        .values(("webhook", id, "headers"))
        .map(|(_, v)| {
            if let Some((k, v)) = v.split_once(':') {
                Ok((
                    HeaderName::from_str(k.trim()).map_err(|err| {
                        format!("Invalid header found in property \"webhook.{id}.headers\": {err}",)
                    })?,
                    HeaderValue::from_str(v.trim()).map_err(|err| {
                        format!("Invalid header found in property \"webhook.{id}.headers\": {err}",)
                    })?,
                ))
            } else {
                Err(format!(
                    "Invalid header found in property \"webhook.{id}.headers\": {v}",
                ))
            }
        })
        .collect::<Result<Vec<(HeaderName, HeaderValue)>, String>>()
        .map_err(|e| config.new_parse_error(("webhook", id, "headers"), e))
        .unwrap_or_default()
    {
        headers.insert(header, value);
    }

    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    if let (Some(name), Some(secret)) = (
        config.value(("webhook", id, "auth.username")),
        config.value(("webhook", id, "auth.secret")),
    ) {
        headers.insert(
            AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{}:{}", name, secret)))
                .parse()
                .unwrap(),
        );
    }

    // Parse webhook events
    let mut events = AHashSet::new();
    let mut parse_errors = Vec::new();
    for (_, value) in config.values(("webhook", id, "events")) {
        match WebhookType::from_str(value) {
            Ok(event) => {
                events.insert(event);
            }
            Err(err) => {
                parse_errors.push(err);
            }
        }
    }
    if !parse_errors.is_empty() {
        config.new_parse_error(
            ("webhook", id, "events"),
            format!("Invalid webhook events: {}", parse_errors.join(", ")),
        );
    }

    let url = config.value_require(("webhook", id, "url"))?.to_string();
    Some(Webhook {
        id: xxhash_rust::xxh3::xxh3_64(url.as_bytes()),
        url,
        timeout: config
            .property_or_default(("webhook", id, "timeout"), "30s")
            .unwrap_or_else(|| Duration::from_secs(30)),
        tls_allow_invalid_certs: config
            .property_or_default(("webhook", id, "allow-invalid-certs"), "false")
            .unwrap_or_default(),
        headers,
        key: config
            .value(("webhook", id, "signature-key"))
            .unwrap_or_default()
            .to_string(),
        throttle: config
            .property_or_default(("webhook", id, "throttle"), "1s")
            .unwrap_or_else(|| Duration::from_secs(1)),
        events,
    })
}

impl FromStr for WebhookType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auth.success" => Ok(Self::AuthSuccess),
            "auth.failure" => Ok(Self::AuthFailure),
            "auth.banned" => Ok(Self::AuthBanned),
            "auth.error" => Ok(Self::AuthError),
            "message.accepted" => Ok(Self::MessageAccepted),
            "message.rejected" => Ok(Self::MessageRejected),
            "message.appended" => Ok(Self::MessageAppended),
            "account.over-quota" => Ok(Self::AccountOverQuota),
            "dsn" => Ok(Self::DSN),
            "double-bounce" => Ok(Self::DoubleBounce),
            "report.incoming.dmarc" => Ok(Self::IncomingDmarcReport),
            "report.incoming.tls" => Ok(Self::IncomingTlsReport),
            "report.incoming.arf" => Ok(Self::IncomingArfReport),
            "report.outgoing" => Ok(Self::OutgoingReport),
            _ => Err(s.to_string()),
        }
    }
}
*/
