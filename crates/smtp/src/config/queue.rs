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

use mail_auth::IpLookupStrategy;

use crate::core::eval::*;

use super::{
    map_expr_token,
    throttle::{ConfigThrottle, ParseTrottleKey},
    Dsn, QueueConfig, QueueOutboundSourceIp, QueueOutboundTimeout, QueueOutboundTls, QueueQuota,
    QueueQuotas, QueueThrottle, RequireOptional, THROTTLE_LOCAL_IP, THROTTLE_MX, THROTTLE_RCPT,
    THROTTLE_RCPT_DOMAIN, THROTTLE_REMOTE_IP, THROTTLE_SENDER, THROTTLE_SENDER_DOMAIN,
};
use utils::{
    config::{
        if_block::IfBlock,
        utils::{AsKey, ConstantValue, NoConstants, ParseValue},
        Config,
    },
    expr::{Constant, Expression, ExpressionItem, Variable},
};

pub trait ConfigQueue {
    fn parse_queue(&self) -> super::Result<QueueConfig>;
    fn parse_queue_throttle(&self) -> super::Result<QueueThrottle>;
    fn parse_queue_quota(&self) -> super::Result<QueueQuotas>;
    fn parse_queue_quota_item(&self, prefix: impl AsKey) -> super::Result<QueueQuota>;
}

impl ConfigQueue for Config {
    fn parse_queue(&self) -> super::Result<QueueConfig> {
        let rcpt_envelope_keys = &[V_RECIPIENT_DOMAIN, V_SENDER, V_SENDER_DOMAIN, V_PRIORITY];
        let sender_envelope_keys = &[V_SENDER, V_SENDER_DOMAIN, V_PRIORITY];
        let mx_envelope_keys = &[
            V_RECIPIENT_DOMAIN,
            V_SENDER,
            V_SENDER_DOMAIN,
            V_PRIORITY,
            V_MX,
        ];
        let host_envelope_keys = &[
            V_RECIPIENT_DOMAIN,
            V_SENDER,
            V_SENDER_DOMAIN,
            V_PRIORITY,
            V_LOCAL_IP,
            V_REMOTE_IP,
            V_MX,
        ];

        let default_hostname = self.value_require("server.hostname")?;

        let config = QueueConfig {
            path: self.property_require("queue.path")?,
            hash: self
                .parse_if_block("queue.hash", |name| {
                    map_expr_token::<NoConstants>(name, sender_envelope_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(32)),

            retry: self
                .parse_if_block("queue.schedule.retry", |name| {
                    map_expr_token::<Duration>(name, host_envelope_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
            notify: self
                .parse_if_block("queue.schedule.notify", |name| {
                    map_expr_token::<Duration>(name, rcpt_envelope_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(86400))),
            expire: self
                .parse_if_block("queue.schedule.expire", |name| {
                    map_expr_token::<Duration>(name, rcpt_envelope_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 86400))),
            hostname: self
                .parse_if_block("queue.outbound.hostname", |name| {
                    map_expr_token::<NoConstants>(name, sender_envelope_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(default_hostname.to_string())),
            max_mx: self
                .parse_if_block("queue.outbound.limits.mx", |name| {
                    map_expr_token::<NoConstants>(name, rcpt_envelope_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(5)),
            max_multihomed: self
                .parse_if_block("queue.outbound.limits.multihomed", |name| {
                    map_expr_token::<NoConstants>(name, rcpt_envelope_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(2)),
            ip_strategy: self
                .parse_if_block("queue.outbound.ip-strategy", |name| {
                    map_expr_token::<IpLookupStrategy>(name, sender_envelope_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(IpLookupStrategy::Ipv4thenIpv6)),
            source_ip: QueueOutboundSourceIp {
                ipv4: self
                    .parse_if_block("queue.outbound.source-ip.v4", |name| {
                        map_expr_token::<NoConstants>(name, mx_envelope_keys)
                    })?
                    .unwrap_or_default(),
                ipv6: self
                    .parse_if_block("queue.outbound.source-ip.v6", |name| {
                        map_expr_token::<NoConstants>(name, mx_envelope_keys)
                    })?
                    .unwrap_or_default(),
            },
            next_hop: self
                .parse_if_block("queue.outbound.next-hop", |name| {
                    map_expr_token::<NoConstants>(name, rcpt_envelope_keys)
                })?
                .unwrap_or_default(),
            tls: QueueOutboundTls {
                dane: self
                    .parse_if_block("queue.outbound.tls.dane", |name| {
                        map_expr_token::<RequireOptional>(name, mx_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(RequireOptional::Optional)),
                mta_sts: self
                    .parse_if_block("queue.outbound.tls.mta-sts", |name| {
                        map_expr_token::<RequireOptional>(name, rcpt_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(RequireOptional::Optional)),
                start: self
                    .parse_if_block("queue.outbound.tls.starttls", |name| {
                        map_expr_token::<RequireOptional>(name, mx_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(RequireOptional::Optional)),
                invalid_certs: self
                    .parse_if_block("queue.outbound.tls.allow-invalid-certs", |name| {
                        map_expr_token::<NoConstants>(name, mx_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(false)),
            },
            throttle: self.parse_queue_throttle()?,
            quota: self.parse_queue_quota()?,
            timeout: QueueOutboundTimeout {
                connect: self
                    .parse_if_block("queue.outbound.timeouts.connect", |name| {
                        map_expr_token::<Duration>(name, host_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
                greeting: self
                    .parse_if_block("queue.outbound.timeouts.greeting", |name| {
                        map_expr_token::<Duration>(name, host_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
                tls: self
                    .parse_if_block("queue.outbound.timeouts.tls", |name| {
                        map_expr_token::<Duration>(name, host_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(3 * 60))),
                ehlo: self
                    .parse_if_block("queue.outbound.timeouts.ehlo", |name| {
                        map_expr_token::<Duration>(name, host_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
                mail: self
                    .parse_if_block("queue.outbound.timeouts.mail-from", |name| {
                        map_expr_token::<Duration>(name, host_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
                rcpt: self
                    .parse_if_block("queue.outbound.timeouts.rcpt-to", |name| {
                        map_expr_token::<Duration>(name, host_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
                data: self
                    .parse_if_block("queue.outbound.timeouts.data", |name| {
                        map_expr_token::<Duration>(name, host_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(10 * 60))),
                mta_sts: self
                    .parse_if_block("queue.outbound.timeouts.mta-sts", |name| {
                        map_expr_token::<Duration>(name, rcpt_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(10 * 60))),
            },
            dsn: Dsn {
                name: self
                    .parse_if_block("report.dsn.from-name", |name| {
                        map_expr_token::<NoConstants>(name, sender_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new("Mail Delivery Subsystem".to_string())),
                address: self
                    .parse_if_block("report.dsn.from-address", |name| {
                        map_expr_token::<NoConstants>(name, sender_envelope_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(format!("MAILER-DAEMON@{default_hostname}"))),
                sign: self
                    .parse_if_block("report.dsn.sign", |name| {
                        map_expr_token::<NoConstants>(name, sender_envelope_keys)
                    })?
                    .unwrap_or_default(),
            },
        };

        Ok(config)
    }

    fn parse_queue_throttle(&self) -> super::Result<QueueThrottle> {
        // Parse throttle
        let mut throttle = QueueThrottle {
            sender: Vec::new(),
            rcpt: Vec::new(),
            host: Vec::new(),
        };
        let envelope_keys = [
            V_RECIPIENT_DOMAIN,
            V_SENDER,
            V_SENDER_DOMAIN,
            V_PRIORITY,
            V_MX,
            V_REMOTE_IP,
            V_LOCAL_IP,
        ];
        let all_throttles = self.parse_throttle(
            "queue.throttle",
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
                || t.expr
                    .items()
                    .iter()
                    .any(|c| matches!(c, ExpressionItem::Variable(V_MX | V_REMOTE_IP | V_LOCAL_IP)))
            {
                throttle.host.push(t);
            } else if (t.keys & (THROTTLE_RCPT_DOMAIN)) != 0
                || t.expr
                    .items()
                    .iter()
                    .any(|c| matches!(c, ExpressionItem::Variable(V_RECIPIENT_DOMAIN)))
            {
                throttle.rcpt.push(t);
            } else {
                throttle.sender.push(t);
            }
        }

        Ok(throttle)
    }

    fn parse_queue_quota(&self) -> super::Result<QueueQuotas> {
        let mut capacities = QueueQuotas {
            sender: Vec::new(),
            rcpt: Vec::new(),
            rcpt_domain: Vec::new(),
        };

        for array_pos in self.sub_keys("queue.quota", "") {
            let quota = self.parse_queue_quota_item(("queue.quota", array_pos))?;

            if (quota.keys & THROTTLE_RCPT) != 0
                || quota
                    .expr
                    .items()
                    .iter()
                    .any(|c| matches!(c, ExpressionItem::Variable(V_RECIPIENT)))
            {
                capacities.rcpt.push(quota);
            } else if (quota.keys & THROTTLE_RCPT_DOMAIN) != 0
                || quota
                    .expr
                    .items()
                    .iter()
                    .any(|c| matches!(c, ExpressionItem::Variable(V_RECIPIENT_DOMAIN)))
            {
                capacities.rcpt_domain.push(quota);
            } else {
                capacities.sender.push(quota);
            }
        }

        Ok(capacities)
    }

    fn parse_queue_quota_item(&self, prefix: impl AsKey) -> super::Result<QueueQuota> {
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
            expr: if let Some(expr) = self.value((&prefix, "match")) {
                Expression::parse((&prefix, "match"), expr, |name| {
                    map_expr_token::<NoConstants>(
                        name,
                        &[
                            V_RECIPIENT,
                            V_RECIPIENT_DOMAIN,
                            V_SENDER,
                            V_SENDER_DOMAIN,
                            V_PRIORITY,
                        ],
                    )
                })?
            } else {
                Expression::default()
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

impl<'x> TryFrom<Variable<'x>> for RequireOptional {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            utils::expr::Variable::Integer(2) => Ok(RequireOptional::Optional),
            utils::expr::Variable::Integer(1) => Ok(RequireOptional::Require),
            utils::expr::Variable::Integer(0) => Ok(RequireOptional::Disable),
            _ => Err(()),
        }
    }
}

impl From<RequireOptional> for Constant {
    fn from(value: RequireOptional) -> Self {
        Constant::Integer(match value {
            RequireOptional::Optional => 2,
            RequireOptional::Require => 1,
            RequireOptional::Disable => 0,
        })
    }
}

impl ConstantValue for RequireOptional {}
