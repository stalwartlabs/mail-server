use std::time::Duration;

use ahash::AHashMap;
use mail_auth::IpLookupStrategy;
use mail_send::Credentials;
use utils::config::{
    utils::{AsKey, ParseValue},
    ServerProtocol,
};

use crate::expr::{if_block::IfBlock, Constant, ConstantValue, Expression, Variable};

use super::Throttle;

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

impl ConstantValue for RequireOptional {}

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

impl ConstantValue for IpLookupStrategy {}
