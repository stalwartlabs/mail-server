use std::time::Duration;

use ahash::AHashMap;
use mail_auth::IpLookupStrategy;
use mail_send::Credentials;
use utils::config::{
    utils::{AsKey, ParseValue},
    Config,
};

use crate::{
    config::server::ServerProtocol,
    expr::{if_block::IfBlock, Constant, ConstantValue, Expression, Variable},
};

use self::throttle::{parse_throttle, parse_throttle_key};

use super::*;

pub struct QueueConfig {
    // Schedule
    pub retry: IfBlock,
    pub notify: IfBlock,
    pub expire: IfBlock,

    // Outbound
    pub hostname: IfBlock,
    pub next_hop: IfBlock,
    pub max_mx: IfBlock,
    pub max_multihomed: IfBlock,
    pub ip_strategy: IfBlock,
    pub source_ip: QueueOutboundSourceIp,
    pub tls: QueueOutboundTls,
    pub dsn: Dsn,

    // Timeouts
    pub timeout: QueueOutboundTimeout,

    // Throttle and Quotas
    pub throttle: QueueThrottle,
    pub quota: QueueQuotas,

    // Relay hosts
    pub relay_hosts: AHashMap<String, RelayHost>,
}

pub struct QueueOutboundSourceIp {
    pub ipv4: IfBlock,
    pub ipv6: IfBlock,
}

pub struct Dsn {
    pub name: IfBlock,
    pub address: IfBlock,
    pub sign: IfBlock,
}

pub struct QueueOutboundTls {
    pub dane: IfBlock,
    pub mta_sts: IfBlock,
    pub start: IfBlock,
    pub invalid_certs: IfBlock,
}

pub struct QueueOutboundTimeout {
    pub connect: IfBlock,
    pub greeting: IfBlock,
    pub tls: IfBlock,
    pub ehlo: IfBlock,
    pub mail: IfBlock,
    pub rcpt: IfBlock,
    pub data: IfBlock,
    pub mta_sts: IfBlock,
}

#[derive(Debug)]
pub struct QueueThrottle {
    pub sender: Vec<Throttle>,
    pub rcpt: Vec<Throttle>,
    pub host: Vec<Throttle>,
}

pub struct QueueQuotas {
    pub sender: Vec<QueueQuota>,
    pub rcpt: Vec<QueueQuota>,
    pub rcpt_domain: Vec<QueueQuota>,
}

pub struct QueueQuota {
    pub expr: Expression,
    pub keys: u16,
    pub size: Option<usize>,
    pub messages: Option<usize>,
}

pub struct RelayHost {
    pub address: String,
    pub port: u16,
    pub protocol: ServerProtocol,
    pub auth: Option<Credentials<String>>,
    pub tls_implicit: bool,
    pub tls_allow_invalid_certs: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum RequireOptional {
    #[default]
    Optional,
    Require,
    Disable,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            retry: IfBlock::new(Duration::from_secs(5 * 60)),
            notify: IfBlock::new(Duration::from_secs(86400)),
            expire: IfBlock::new(Duration::from_secs(5 * 86400)),
            hostname: IfBlock::new("localhost".to_string()),
            next_hop: Default::default(),
            max_mx: IfBlock::new(5),
            max_multihomed: IfBlock::new(2),
            ip_strategy: IfBlock::new(IpLookupStrategy::Ipv4thenIpv6),
            source_ip: QueueOutboundSourceIp {
                ipv4: Default::default(),
                ipv6: Default::default(),
            },
            tls: QueueOutboundTls {
                dane: IfBlock::new(RequireOptional::Optional),
                mta_sts: IfBlock::new(RequireOptional::Optional),
                start: IfBlock::new(RequireOptional::Optional),
                invalid_certs: IfBlock::new(false),
            },
            dsn: Dsn {
                name: IfBlock::new("Mail Delivery Subsystem".to_string()),
                address: IfBlock::new("MAILER-DAEMON@localhost".to_string()),
                sign: Default::default(),
            },
            timeout: QueueOutboundTimeout {
                connect: IfBlock::new(Duration::from_secs(5 * 60)),
                greeting: IfBlock::new(Duration::from_secs(5 * 60)),
                tls: IfBlock::new(Duration::from_secs(3 * 60)),
                ehlo: IfBlock::new(Duration::from_secs(5 * 60)),
                mail: IfBlock::new(Duration::from_secs(5 * 60)),
                rcpt: IfBlock::new(Duration::from_secs(5 * 60)),
                data: IfBlock::new(Duration::from_secs(10 * 60)),
                mta_sts: IfBlock::new(Duration::from_secs(10 * 60)),
            },
            throttle: QueueThrottle {
                sender: Default::default(),
                rcpt: Default::default(),
                host: Default::default(),
            },
            quota: QueueQuotas {
                sender: Default::default(),
                rcpt: Default::default(),
                rcpt_domain: Default::default(),
            },
            relay_hosts: Default::default(),
        }
    }
}

impl QueueConfig {
    pub fn parse(config: &mut Config) -> Self {
        let mut queue = QueueConfig::default();
        let rcpt_vars = TokenMap::default().with_smtp_variables(&[
            V_RECIPIENT_DOMAIN,
            V_SENDER,
            V_SENDER_DOMAIN,
            V_PRIORITY,
        ]);
        let sender_vars =
            TokenMap::default().with_smtp_variables(&[V_SENDER, V_SENDER_DOMAIN, V_PRIORITY]);
        let mx_vars = TokenMap::default().with_smtp_variables(&[
            V_RECIPIENT_DOMAIN,
            V_SENDER,
            V_SENDER_DOMAIN,
            V_PRIORITY,
            V_MX,
        ]);
        let host_vars = TokenMap::default().with_smtp_variables(&[
            V_RECIPIENT_DOMAIN,
            V_SENDER,
            V_SENDER_DOMAIN,
            V_PRIORITY,
            V_LOCAL_IP,
            V_REMOTE_IP,
            V_MX,
        ]);
        let ip_strategy_vars = sender_vars.clone().with_constants::<IpLookupStrategy>();
        let dane_vars = mx_vars.clone().with_constants::<RequireOptional>();
        let mta_sts_vars = rcpt_vars.clone().with_constants::<RequireOptional>();

        // Parse default server hostname
        if let Some(hostname) = parse_server_hostname(config) {
            queue.hostname = hostname.into_default("queue.outbound.hostname");
        }

        for (value, key, token_map) in [
            (&mut queue.retry, "queue.schedule.retry", &host_vars),
            (&mut queue.notify, "queue.schedule.notify", &rcpt_vars),
            (&mut queue.expire, "queue.schedule.expire", &rcpt_vars),
            (&mut queue.hostname, "queue.outbound.hostname", &sender_vars),
            (&mut queue.max_mx, "queue.outbound.limits.mx", &rcpt_vars),
            (
                &mut queue.max_multihomed,
                "queue.outbound.limits.multihomed",
                &rcpt_vars,
            ),
            (
                &mut queue.ip_strategy,
                "queue.outbound.ip-strategy",
                &ip_strategy_vars,
            ),
            (
                &mut queue.source_ip.ipv4,
                "queue.outbound.source-ip.v4",
                &mx_vars,
            ),
            (
                &mut queue.source_ip.ipv6,
                "queue.outbound.source-ip.v6",
                &mx_vars,
            ),
            (&mut queue.next_hop, "queue.outbound.next-hop", &rcpt_vars),
            (&mut queue.tls.dane, "queue.outbound.tls.dane", &dane_vars),
            (
                &mut queue.tls.mta_sts,
                "queue.outbound.tls.mta-sts",
                &mta_sts_vars,
            ),
            (
                &mut queue.tls.start,
                "queue.outbound.tls.starttls",
                &dane_vars,
            ),
            (
                &mut queue.tls.invalid_certs,
                "queue.outbound.tls.allow-invalid-certs",
                &mx_vars,
            ),
            (
                &mut queue.timeout.connect,
                "queue.outbound.timeouts.connect",
                &host_vars,
            ),
            (
                &mut queue.timeout.greeting,
                "queue.outbound.timeouts.greeting",
                &host_vars,
            ),
            (
                &mut queue.timeout.tls,
                "queue.outbound.timeouts.tls",
                &host_vars,
            ),
            (
                &mut queue.timeout.ehlo,
                "queue.outbound.timeouts.ehlo",
                &host_vars,
            ),
            (
                &mut queue.timeout.mail,
                "queue.outbound.timeouts.mail-from",
                &host_vars,
            ),
            (
                &mut queue.timeout.rcpt,
                "queue.outbound.timeouts.rcpt-to",
                &host_vars,
            ),
            (
                &mut queue.timeout.data,
                "queue.outbound.timeouts.data",
                &host_vars,
            ),
            (
                &mut queue.timeout.mta_sts,
                "queue.outbound.timeouts.mta-sts",
                &host_vars,
            ),
            (&mut queue.dsn.name, "report.dsn.from-name", &sender_vars),
            (
                &mut queue.dsn.address,
                "report.dsn.from-address",
                &sender_vars,
            ),
            (&mut queue.dsn.sign, "report.dsn.sign", &sender_vars),
        ] {
            if let Some(if_block) = IfBlock::try_parse(config, key, token_map) {
                *value = if_block;
            }
        }

        // Parse queue quotas and throttles
        queue.throttle = parse_queue_throttle(config);
        queue.quota = parse_queue_quota(config);

        // Parse relay hosts
        queue.relay_hosts = config
            .sub_keys("remote", ".address")
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|id| parse_relay_host(config, &id).map(|host| (id, host)))
            .collect();

        // Add local delivery host
        queue.relay_hosts.insert(
            "local".to_string(),
            RelayHost {
                address: String::new(),
                port: 0,
                protocol: ServerProtocol::Http,
                tls_implicit: Default::default(),
                tls_allow_invalid_certs: Default::default(),
                auth: None,
            },
        );

        queue
    }
}

fn parse_relay_host(config: &mut Config, id: &str) -> Option<RelayHost> {
    Some(RelayHost {
        address: config.property_require_(("remote", id, "address"))?,
        port: config
            .property_require_(("remote", id, "port"))
            .unwrap_or(25),
        protocol: config
            .property_require_(("remote", id, "protocol"))
            .unwrap_or(ServerProtocol::Smtp),
        auth: if let (Some(username), Some(secret)) = (
            config.value(("remote", id, "auth.username")),
            config.value(("remote", id, "auth.secret")),
        ) {
            Credentials::new(username.to_string(), secret.to_string()).into()
        } else {
            None
        },
        tls_implicit: config
            .property_(("remote", id, "tls.implicit"))
            .unwrap_or(true),
        tls_allow_invalid_certs: config
            .property_(("remote", id, "tls.allow-invalid-certs"))
            .unwrap_or(false),
    })
}

fn parse_queue_throttle(config: &mut Config) -> QueueThrottle {
    // Parse throttle
    let mut throttle = QueueThrottle {
        sender: Vec::new(),
        rcpt: Vec::new(),
        host: Vec::new(),
    };

    let all_throttles = parse_throttle(
        config,
        "queue.throttle",
        &TokenMap::default().with_smtp_variables(&[
            V_RECIPIENT_DOMAIN,
            V_SENDER,
            V_SENDER_DOMAIN,
            V_PRIORITY,
            V_MX,
            V_REMOTE_IP,
            V_LOCAL_IP,
        ]),
        THROTTLE_RCPT_DOMAIN
            | THROTTLE_SENDER
            | THROTTLE_SENDER_DOMAIN
            | THROTTLE_MX
            | THROTTLE_REMOTE_IP
            | THROTTLE_LOCAL_IP,
    );
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

    throttle
}

fn parse_queue_quota(config: &mut Config) -> QueueQuotas {
    let mut capacities = QueueQuotas {
        sender: Vec::new(),
        rcpt: Vec::new(),
        rcpt_domain: Vec::new(),
    };

    for quota_id in config
        .sub_keys("queue.quota", "")
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
    {
        if let Some(quota) = parse_queue_quota_item(config, ("queue.quota", &quota_id)) {
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
    }

    capacities
}

fn parse_queue_quota_item(config: &mut Config, prefix: impl AsKey) -> Option<QueueQuota> {
    let prefix = prefix.as_key();
    let mut keys = 0;
    for (key_, value) in config
        .values((&prefix, "key"))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<Vec<_>>()
    {
        match parse_throttle_key(&value) {
            Ok(key) => {
                if (key
                    & (THROTTLE_RCPT_DOMAIN
                        | THROTTLE_RCPT
                        | THROTTLE_SENDER
                        | THROTTLE_SENDER_DOMAIN))
                    != 0
                {
                    keys |= key;
                } else {
                    let err = format!("Quota key {value:?} is not available in this context");
                    config.new_build_error(key_, err);
                }
            }
            Err(err) => {
                config.new_parse_error(key_, err);
            }
        }
    }

    let quota = QueueQuota {
        expr: Expression::try_parse(
            config,
            (prefix.as_str(), "match"),
            &TokenMap::default().with_smtp_variables(&[
                V_RECIPIENT,
                V_RECIPIENT_DOMAIN,
                V_SENDER,
                V_SENDER_DOMAIN,
                V_PRIORITY,
            ]),
        )
        .unwrap_or_default(),
        keys,
        size: config
            .property_::<usize>((prefix.as_str(), "size"))
            .filter(|&v| v > 0),
        messages: config
            .property_::<usize>((prefix.as_str(), "messages"))
            .filter(|&v| v > 0),
    };

    // Validate
    if quota.size.is_none() && quota.messages.is_none() {
        config.new_parse_error(
            prefix.as_str(),
            concat!(
                "Queue quota needs to define a ",
                "valid 'size' and/or 'messages' property."
            )
            .to_string(),
        );
        None
    } else {
        Some(quota)
    }
}

impl ParseValue for RequireOptional {
    fn parse_value(key: impl AsKey, value: &str) -> utils::config::Result<Self> {
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
            Variable::Integer(2) => Ok(RequireOptional::Optional),
            Variable::Integer(1) => Ok(RequireOptional::Require),
            Variable::Integer(0) => Ok(RequireOptional::Disable),
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

impl ConstantValue for RequireOptional {
    fn add_constants(token_map: &mut crate::expr::tokenizer::TokenMap) {
        token_map
            .add_constant("optional", RequireOptional::Optional)
            .add_constant("require", RequireOptional::Require)
            .add_constant("required", RequireOptional::Require)
            .add_constant("disable", RequireOptional::Disable)
            .add_constant("disabled", RequireOptional::Disable)
            .add_constant("none", RequireOptional::Disable)
            .add_constant("false", RequireOptional::Disable);
    }
}

impl<'x> TryFrom<Variable<'x>> for IpLookupStrategy {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Integer(value) => match value {
                2 => Ok(IpLookupStrategy::Ipv4Only),
                3 => Ok(IpLookupStrategy::Ipv6Only),
                4 => Ok(IpLookupStrategy::Ipv6thenIpv4),
                5 => Ok(IpLookupStrategy::Ipv4thenIpv6),
                _ => Err(()),
            },
            Variable::String(value) => IpLookupStrategy::parse_value("", &value).map_err(|_| ()),
            _ => Err(()),
        }
    }
}

impl From<IpLookupStrategy> for Constant {
    fn from(value: IpLookupStrategy) -> Self {
        Constant::Integer(match value {
            IpLookupStrategy::Ipv4Only => 2,
            IpLookupStrategy::Ipv6Only => 3,
            IpLookupStrategy::Ipv6thenIpv4 => 4,
            IpLookupStrategy::Ipv4thenIpv6 => 5,
        })
    }
}

impl ConstantValue for IpLookupStrategy {
    fn add_constants(token_map: &mut crate::expr::tokenizer::TokenMap) {
        token_map
            .add_constant("ipv4_only", IpLookupStrategy::Ipv4Only)
            .add_constant("ipv6_only", IpLookupStrategy::Ipv6Only)
            .add_constant("ipv6_then_ipv4", IpLookupStrategy::Ipv6thenIpv4)
            .add_constant("ipv4_then_ipv6", IpLookupStrategy::Ipv4thenIpv6);
    }
}

impl std::fmt::Debug for RelayHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayHost")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("protocol", &self.protocol)
            .field("tls_implicit", &self.tls_implicit)
            .field("tls_allow_invalid_certs", &self.tls_allow_invalid_certs)
            .finish()
    }
}
