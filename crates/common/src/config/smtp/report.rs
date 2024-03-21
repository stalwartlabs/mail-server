use std::time::Duration;

use utils::{
    config::utils::{AsKey, ParseValue},
    snowflake::SnowflakeIdGenerator,
};

use crate::expr::{if_block::IfBlock, Constant, ConstantValue, Variable};

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

impl ConstantValue for AggregateFrequency {}
