use std::time::Duration;

use utils::{
    config::{
        utils::{AsKey, ParseValue},
        Config,
    },
    snowflake::SnowflakeIdGenerator,
};

use crate::expr::{if_block::IfBlock, tokenizer::TokenMap, Constant, ConstantValue, Variable};

use super::*;

pub struct ReportConfig {
    pub submitter: IfBlock,
    pub analysis: ReportAnalysis,

    pub dkim: Report,
    pub spf: Report,
    pub dmarc: Report,
    pub dmarc_aggregate: AggregateReport,
    pub tls: AggregateReport,
}

pub struct ReportAnalysis {
    pub addresses: Vec<AddressMatch>,
    pub forward: bool,
    pub store: Option<Duration>,
    pub report_id: SnowflakeIdGenerator,
}

pub enum AddressMatch {
    StartsWith(String),
    EndsWith(String),
    Equals(String),
}

pub struct AggregateReport {
    pub name: IfBlock,
    pub address: IfBlock,
    pub org_name: IfBlock,
    pub contact_info: IfBlock,
    pub send: IfBlock,
    pub sign: IfBlock,
    pub max_size: IfBlock,
}

pub struct Report {
    pub name: IfBlock,
    pub address: IfBlock,
    pub subject: IfBlock,
    pub sign: IfBlock,
    pub send: IfBlock,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AggregateFrequency {
    Hourly,
    Daily,
    Weekly,
    #[default]
    Never,
}

impl ReportConfig {
    pub fn parse(config: &mut Config) -> Self {
        let sender_vars = TokenMap::default().with_smtp_variables(&[
            V_SENDER,
            V_SENDER_DOMAIN,
            V_PRIORITY,
            V_AUTHENTICATED_AS,
            V_LISTENER,
            V_REMOTE_IP,
            V_LOCAL_IP,
        ]);
        let rcpt_vars = TokenMap::default().with_smtp_variables(&[
            V_SENDER,
            V_SENDER_DOMAIN,
            V_PRIORITY,
            V_REMOTE_IP,
            V_LOCAL_IP,
            V_RECIPIENT_DOMAIN,
        ]);

        let default_hostname_if_block = parse_server_hostname(config);
        let default_hostname = default_hostname_if_block
            .as_ref()
            .and_then(|i| i.default_string())
            .unwrap_or("localhost")
            .to_string();

        Self {
            submitter: IfBlock::try_parse(
                config,
                "report.submitter",
                &TokenMap::default().with_smtp_variables(&[V_RECIPIENT_DOMAIN]),
            )
            .unwrap_or_else(|| {
                default_hostname_if_block
                    .map(|i| i.into_default("report.submitter"))
                    .unwrap_or_else(|| IfBlock::new("localhost".to_string()))
            }),
            analysis: ReportAnalysis {
                addresses: config
                    .properties_::<AddressMatch>("report.analysis.addresses")
                    .into_iter()
                    .map(|(_, m)| m)
                    .collect(),
                forward: config.property_("report.analysis.forward").unwrap_or(true),
                store: config.property_("report.analysis.store"),
                report_id: config
                    .property_::<u64>("storage.cluster.node-id")
                    .map(SnowflakeIdGenerator::with_node_id)
                    .unwrap_or_default(),
            },
            dkim: Report::parse(config, "dkim", &default_hostname, &sender_vars),
            spf: Report::parse(config, "spf", &default_hostname, &sender_vars),
            dmarc: Report::parse(config, "dmarc", &default_hostname, &sender_vars),
            dmarc_aggregate: AggregateReport::parse(
                config,
                "dmarc",
                &default_hostname,
                &sender_vars.with_constants::<AggregateFrequency>(),
            ),
            tls: AggregateReport::parse(
                config,
                "tls",
                &default_hostname,
                &rcpt_vars.with_constants::<AggregateFrequency>(),
            ),
        }
    }
}

impl Report {
    pub fn parse(
        config: &mut Config,
        id: &str,
        default_hostname: &str,
        token_map: &TokenMap,
    ) -> Self {
        let mut report = Self {
            name: IfBlock::new(format!("{} Reporting", id.to_ascii_uppercase())),
            address: IfBlock::new(format!("MAILER-DAEMON@{default_hostname}")),
            subject: IfBlock::new(format!("{} Report", id.to_ascii_uppercase())),
            sign: Default::default(),
            send: Default::default(),
        };
        for (value, key) in [
            (&mut report.name, "from-name"),
            (&mut report.address, "from-address"),
            (&mut report.subject, "subject"),
            (&mut report.sign, "sign"),
            (&mut report.send, "send"),
        ] {
            if let Some(if_block) = IfBlock::try_parse(config, ("report", id, key), token_map) {
                *value = if_block;
            }
        }

        report
    }
}

impl AggregateReport {
    pub fn parse(
        config: &mut Config,
        id: &str,
        default_hostname: &str,
        token_map: &TokenMap,
    ) -> Self {
        let rcpt_vars = TokenMap::default().with_smtp_variables(&[V_RECIPIENT_DOMAIN]);

        let mut report = Self {
            name: IfBlock::new(format!("{} Aggregate Report", id.to_ascii_uppercase())),
            address: IfBlock::new(format!("noreply-{id}@{default_hostname}")),
            org_name: Default::default(),
            contact_info: Default::default(),
            send: IfBlock::new(AggregateFrequency::Never),
            sign: Default::default(),
            max_size: IfBlock::new(25 * 1024 * 1024),
        };

        for (value, key, token_map) in [
            (&mut report.name, "aggregate.from-name", &rcpt_vars),
            (&mut report.address, "aggregate.from-address", &rcpt_vars),
            (&mut report.org_name, "aggregate.org-name", &rcpt_vars),
            (
                &mut report.contact_info,
                "aggregate.contact-info",
                &rcpt_vars,
            ),
            (&mut report.send, "aggregate.send", token_map),
            (&mut report.sign, "aggregate.sign", &rcpt_vars),
            (&mut report.max_size, "aggregate.max-size", &rcpt_vars),
        ] {
            if let Some(if_block) = IfBlock::try_parse(config, ("report", id, key), token_map) {
                *value = if_block;
            }
        }

        report
    }
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            submitter: IfBlock::new("localhost".to_string()),
            analysis: ReportAnalysis {
                addresses: Default::default(),
                forward: true,
                store: None,
                report_id: SnowflakeIdGenerator::new(),
            },
            dkim: Default::default(),
            spf: Default::default(),
            dmarc: Default::default(),
            dmarc_aggregate: Default::default(),
            tls: Default::default(),
        }
    }
}

impl Default for Report {
    fn default() -> Self {
        Self {
            name: IfBlock::new("Mail Delivery Subsystem".to_string()),
            address: IfBlock::new("MAILER-DAEMON@localhost".to_string()),
            subject: IfBlock::new("Report".to_string()),
            sign: Default::default(),
            send: Default::default(),
        }
    }
}

impl Default for AggregateReport {
    fn default() -> Self {
        Self {
            name: IfBlock::new("Reporting Subsystem".to_string()),
            address: IfBlock::new("no-replyN@localhost".to_string()),
            org_name: Default::default(),
            contact_info: Default::default(),
            send: IfBlock::new(AggregateFrequency::Never),
            sign: Default::default(),
            max_size: IfBlock::new(25 * 1024 * 1024),
        }
    }
}

impl ParseValue for AggregateFrequency {
    fn parse_value(key: impl AsKey, value: &str) -> utils::config::Result<Self> {
        match value {
            "daily" | "day" => Ok(AggregateFrequency::Daily),
            "hourly" | "hour" => Ok(AggregateFrequency::Hourly),
            "weekly" | "week" => Ok(AggregateFrequency::Weekly),
            "never" | "disable" | "false" => Ok(AggregateFrequency::Never),
            _ => Err(format!(
                "Invalid aggregate frequency value {:?} for key {:?}.",
                value,
                key.as_key()
            )),
        }
    }
}

impl From<AggregateFrequency> for Constant {
    fn from(value: AggregateFrequency) -> Self {
        match value {
            AggregateFrequency::Never => 0.into(),
            AggregateFrequency::Hourly => 2.into(),
            AggregateFrequency::Daily => 3.into(),
            AggregateFrequency::Weekly => 4.into(),
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for AggregateFrequency {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Integer(0) => Ok(AggregateFrequency::Never),
            Variable::Integer(2) => Ok(AggregateFrequency::Hourly),
            Variable::Integer(3) => Ok(AggregateFrequency::Daily),
            Variable::Integer(4) => Ok(AggregateFrequency::Weekly),
            _ => Err(()),
        }
    }
}

impl ConstantValue for AggregateFrequency {
    fn add_constants(token_map: &mut crate::expr::tokenizer::TokenMap) {
        token_map
            .add_constant("never", AggregateFrequency::Never)
            .add_constant("hourly", AggregateFrequency::Hourly)
            .add_constant("hour", AggregateFrequency::Hourly)
            .add_constant("daily", AggregateFrequency::Daily)
            .add_constant("day", AggregateFrequency::Daily)
            .add_constant("weekly", AggregateFrequency::Weekly)
            .add_constant("week", AggregateFrequency::Weekly)
            .add_constant("never", AggregateFrequency::Never)
            .add_constant("disable", AggregateFrequency::Never)
            .add_constant("false", AggregateFrequency::Never);
    }
}

impl ParseValue for AddressMatch {
    fn parse_value(key: impl AsKey, value: &str) -> utils::config::Result<Self> {
        if let Some(value) = value.strip_prefix('*').map(|v| v.trim()) {
            if !value.is_empty() {
                return Ok(AddressMatch::EndsWith(value.to_lowercase()));
            }
        } else if let Some(value) = value.strip_suffix('*').map(|v| v.trim()) {
            if !value.is_empty() {
                return Ok(AddressMatch::StartsWith(value.to_lowercase()));
            }
        } else if value.contains('@') {
            return Ok(AddressMatch::Equals(value.trim().to_lowercase()));
        }
        Err(format!(
            "Invalid address match value {:?} for key {:?}.",
            value,
            key.as_key()
        ))
    }
}
