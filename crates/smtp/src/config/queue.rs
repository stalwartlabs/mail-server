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

use std::time::Duration;

use directory::memory::MemoryDirectory;
use mail_send::Credentials;

use super::{
    condition::ConfigCondition,
    if_block::ConfigIf,
    throttle::{ConfigThrottle, ParseTrottleKey},
    *,
};
use utils::config::{
    utils::{AsKey, ParseValue},
    Config,
};

pub trait ConfigQueue {
    fn parse_queue(&self, ctx: &ConfigContext) -> super::Result<QueueConfig>;
    fn parse_queue_throttle(&self, ctx: &ConfigContext) -> super::Result<QueueThrottle>;
    fn parse_queue_quota(&self, ctx: &ConfigContext) -> super::Result<QueueQuotas>;
    fn parse_queue_quota_item(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
    ) -> super::Result<QueueQuota>;
}

impl ConfigQueue for Config {
    fn parse_queue(&self, ctx: &ConfigContext) -> super::Result<QueueConfig> {
        let rcpt_envelope_keys = [
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
        ];
        let sender_envelope_keys = [
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
        ];
        let mx_envelope_keys = [
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
            EnvelopeKey::Mx,
        ];
        let host_envelope_keys = [
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
            EnvelopeKey::LocalIp,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::Mx,
        ];

        let next_hop = self
            .parse_if_block::<Option<String>>("queue.outbound.next-hop", ctx, &rcpt_envelope_keys)?
            .unwrap_or_else(|| IfBlock::new(None));

        let default_hostname = self.value_require("server.hostname")?;

        let config = QueueConfig {
            path: self
                .parse_if_block("queue.path", ctx, &sender_envelope_keys)?
                .ok_or("Missing \"queue.path\" property.")?,
            hash: self
                .parse_if_block("queue.hash", ctx, &sender_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(32)),

            retry: self
                .parse_if_block("queue.schedule.retry", ctx, &host_envelope_keys)?
                .unwrap_or_else(|| {
                    IfBlock::new(vec![
                        Duration::from_secs(60),
                        Duration::from_secs(2 * 60),
                        Duration::from_secs(5 * 60),
                        Duration::from_secs(10 * 60),
                        Duration::from_secs(15 * 60),
                        Duration::from_secs(30 * 60),
                        Duration::from_secs(3600),
                        Duration::from_secs(2 * 3600),
                    ])
                }),
            notify: self
                .parse_if_block("queue.schedule.notify", ctx, &rcpt_envelope_keys)?
                .unwrap_or_else(|| {
                    IfBlock::new(vec![
                        Duration::from_secs(86400),
                        Duration::from_secs(3 * 86400),
                    ])
                }),
            expire: self
                .parse_if_block("queue.schedule.expire", ctx, &rcpt_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 86400))),
            hostname: self
                .parse_if_block("queue.outbound.hostname", ctx, &sender_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(default_hostname.to_string())),
            max_mx: self
                .parse_if_block("queue.outbound.limits.mx", ctx, &rcpt_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(5)),
            max_multihomed: self
                .parse_if_block("queue.outbound.limits.multihomed", ctx, &rcpt_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(2)),
            ip_strategy: self
                .parse_if_block("queue.outbound.ip-strategy", ctx, &sender_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(IpLookupStrategy::Ipv4thenIpv6)),
            source_ip: QueueOutboundSourceIp {
                ipv4: self
                    .parse_if_block("queue.outbound.source-ip.v4", ctx, &mx_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(Vec::new())),
                ipv6: self
                    .parse_if_block("queue.outbound.source-ip.v6", ctx, &mx_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(Vec::new())),
            },
            next_hop: next_hop.into_relay_host(ctx)?,
            tls: QueueOutboundTls {
                dane: self
                    .parse_if_block("queue.outbound.tls.dane", ctx, &mx_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(RequireOptional::Optional)),
                mta_sts: self
                    .parse_if_block("queue.outbound.tls.mta-sts", ctx, &rcpt_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(RequireOptional::Optional)),
                start: self
                    .parse_if_block("queue.outbound.tls.starttls", ctx, &mx_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(RequireOptional::Optional)),
            },
            throttle: self.parse_queue_throttle(ctx)?,
            quota: self.parse_queue_quota(ctx)?,
            timeout: QueueOutboundTimeout {
                connect: self
                    .parse_if_block("queue.outbound.timeouts.connect", ctx, &host_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
                greeting: self
                    .parse_if_block("queue.outbound.timeouts.greeting", ctx, &host_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
                tls: self
                    .parse_if_block("queue.outbound.timeouts.tls", ctx, &host_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(3 * 60))),
                ehlo: self
                    .parse_if_block("queue.outbound.timeouts.ehlo", ctx, &host_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
                mail: self
                    .parse_if_block(
                        "queue.outbound.timeouts.mail-from",
                        ctx,
                        &host_envelope_keys,
                    )?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
                rcpt: self
                    .parse_if_block("queue.outbound.timeouts.rcpt-to", ctx, &host_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
                data: self
                    .parse_if_block("queue.outbound.timeouts.data", ctx, &host_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(10 * 60))),
                mta_sts: self
                    .parse_if_block("queue.outbound.timeouts.mta-sts", ctx, &rcpt_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(10 * 60))),
            },
            dsn: Dsn {
                name: self
                    .parse_if_block("report.dsn.from-name", ctx, &sender_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new("Mail Delivery Subsystem".to_string())),
                address: self
                    .parse_if_block("report.dsn.from-address", ctx, &sender_envelope_keys)?
                    .unwrap_or_else(|| IfBlock::new(format!("MAILER-DAEMON@{default_hostname}"))),
                sign: self
                    .parse_if_block::<Vec<String>>("report.dsn.sign", ctx, &sender_envelope_keys)?
                    .unwrap_or_default()
                    .map_if_block(&ctx.signers, "report.dsn.sign", "signature")?,
            },
            management_lookup: if let Some(id) = self.value("management.directory") {
                ctx.directory
                    .directories
                    .get(id)
                    .ok_or_else(|| {
                        format!("Directory {id:?} not found for key \"management.directory\".")
                    })?
                    .clone()
            } else {
                Arc::new(MemoryDirectory::default())
            },
        };

        if config.retry.has_empty_list() {
            Err("Property \"queue.schedule.retry\" cannot contain empty lists.".to_string())
        } else if config.notify.has_empty_list() {
            Err("Property \"queue.schedule.notify\" cannot contain empty lists.".to_string())
        } else {
            Ok(config)
        }
    }

    fn parse_queue_throttle(&self, ctx: &ConfigContext) -> super::Result<QueueThrottle> {
        // Parse throttle
        let mut throttle = QueueThrottle {
            sender: Vec::new(),
            rcpt: Vec::new(),
            host: Vec::new(),
        };
        let envelope_keys = [
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
            EnvelopeKey::Mx,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
        ];
        let all_throttles = self.parse_throttle(
            "queue.throttle",
            ctx,
            &envelope_keys,
            THROTTLE_RCPT_DOMAIN
                | THROTTLE_SENDER
                | THROTTLE_SENDER_DOMAIN
                | THROTTLE_MX
                | THROTTLE_REMOTE_IP
                | THROTTLE_LOCAL_IP,
        )?;
        for t in all_throttles {
            if (t.keys & (THROTTLE_MX | THROTTLE_REMOTE_IP | THROTTLE_LOCAL_IP)) != 0
                || t.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::Mx | EnvelopeKey::RemoteIp | EnvelopeKey::LocalIp,
                            ..
                        }
                    )
                })
            {
                throttle.host.push(t);
            } else if (t.keys & (THROTTLE_RCPT_DOMAIN)) != 0
                || t.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::RecipientDomain,
                            ..
                        }
                    )
                })
            {
                throttle.rcpt.push(t);
            } else {
                throttle.sender.push(t);
            }
        }

        Ok(throttle)
    }

    fn parse_queue_quota(&self, ctx: &ConfigContext) -> super::Result<QueueQuotas> {
        let mut capacities = QueueQuotas {
            sender: Vec::new(),
            rcpt: Vec::new(),
            rcpt_domain: Vec::new(),
        };

        for array_pos in self.sub_keys("queue.quota") {
            let quota = self.parse_queue_quota_item(("queue.quota", array_pos), ctx)?;

            if (quota.keys & THROTTLE_RCPT) != 0
                || quota.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::Recipient,
                            ..
                        }
                    )
                })
            {
                capacities.rcpt.push(quota);
            } else if (quota.keys & THROTTLE_RCPT_DOMAIN) != 0
                || quota.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::RecipientDomain,
                            ..
                        }
                    )
                })
            {
                capacities.rcpt_domain.push(quota);
            } else {
                capacities.sender.push(quota);
            }
        }

        Ok(capacities)
    }

    fn parse_queue_quota_item(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
    ) -> super::Result<QueueQuota> {
        let prefix = prefix.as_key();
        let mut keys = 0;
        for (key_, value) in self.values((&prefix, "key")) {
            let key = value.parse_throttle_key(key_)?;
            if (key
                & (THROTTLE_RCPT_DOMAIN | THROTTLE_RCPT | THROTTLE_SENDER | THROTTLE_SENDER_DOMAIN))
                != 0
            {
                keys |= key;
            } else {
                return Err(format!(
                    "Key {value:?} is not available in this context for property {key_:?}"
                ));
            }
        }

        let quota = QueueQuota {
            conditions: if self.values((&prefix, "match")).next().is_some() {
                self.parse_condition(
                    (&prefix, "match"),
                    ctx,
                    &[
                        EnvelopeKey::Recipient,
                        EnvelopeKey::RecipientDomain,
                        EnvelopeKey::Sender,
                        EnvelopeKey::SenderDomain,
                        EnvelopeKey::Priority,
                    ],
                )?
            } else {
                Conditions {
                    conditions: Vec::with_capacity(0),
                }
            },
            keys,
            size: self
                .property::<usize>((prefix.as_str(), "size"))?
                .filter(|&v| v > 0),
            messages: self
                .property::<usize>((prefix.as_str(), "messages"))?
                .filter(|&v| v > 0),
        };

        // Validate
        if quota.size.is_none() && quota.messages.is_none() {
            Err(format!(
                concat!(
                    "Queue quota {:?} needs to define a ",
                    "valid 'size' and/or 'messages' property."
                ),
                prefix
            ))
        } else {
            Ok(quota)
        }
    }
}

impl IfBlock<Option<String>> {
    pub fn into_relay_host(self, ctx: &ConfigContext) -> super::Result<IfBlock<Option<RelayHost>>> {
        Ok(IfBlock {
            if_then: {
                let mut if_then = Vec::with_capacity(self.if_then.len());

                for i in self.if_then {
                    if_then.push(IfThen {
                        conditions: i.conditions,
                        then: if let Some(then) = i.then {
                            Some(
                                ctx.hosts
                                    .get(&then)
                                    .ok_or_else(|| {
                                        format!(
                                            "Host {then:?} not found for property \"queue.next-hop\".",
                                        )
                                    })?
                                    .into(),
                            )
                        } else {
                            None
                        },
                    });
                }

                if_then
            },
            default: if let Some(default) = self.default {
                Some(
                    ctx.hosts
                        .get(&default)
                        .ok_or_else(|| {
                            format!(
                                "Relay host {default:?} not found for property \"queue.next-hop\".",
                            )
                        })?
                        .into(),
                )
            } else {
                None
            },
        })
    }
}

impl From<&Host> for RelayHost {
    fn from(host: &Host) -> Self {
        RelayHost {
            address: host.address.to_string(),
            port: host.port,
            protocol: host.protocol,
            auth: if let (Some(username), Some(secret)) = (&host.username, &host.secret) {
                Credentials::new(username.to_string(), secret.to_string()).into()
            } else {
                None
            },
            tls_implicit: host.tls_implicit,
            tls_allow_invalid_certs: host.tls_allow_invalid_certs,
        }
    }
}

impl ParseValue for RequireOptional {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        match value {
            "optional" => Ok(RequireOptional::Optional),
            "require" | "required" => Ok(RequireOptional::Require),
            "disable" | "disabled" | "none" | "false" => Ok(RequireOptional::Disable),
            _ => Err(format!(
                "Invalid TLS option value {:?} for key {:?}.",
                value,
                key.as_key()
            )),
        }
    }
}
