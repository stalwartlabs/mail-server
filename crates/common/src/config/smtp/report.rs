/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use utils::config::{utils::ParseValue, Config};

use crate::expr::{if_block::IfBlock, tokenizer::TokenMap, Constant, ConstantValue, Variable};

use super::*;

#[derive(Clone)]
pub struct ReportConfig {
    pub submitter: IfBlock,
    pub analysis: ReportAnalysis,

    pub dkim: Report,
    pub spf: Report,
    pub dmarc: Report,
    pub dmarc_aggregate: AggregateReport,
    pub tls: AggregateReport,
}

#[derive(Clone)]
pub struct ReportAnalysis {
    pub addresses: Vec<AddressMatch>,
    pub forward: bool,
    pub store: Option<Duration>,
}

#[derive(Clone)]
pub enum AddressMatch {
    StartsWith(String),
    EndsWith(String),
    Equals(String),
}

#[derive(Clone)]
pub struct AggregateReport {
    pub name: IfBlock,
    pub address: IfBlock,
    pub org_name: IfBlock,
    pub contact_info: IfBlock,
    pub send: IfBlock,
    pub sign: IfBlock,
    pub max_size: IfBlock,
}

#[derive(Clone)]
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
        let sender_vars = TokenMap::default().with_variables(SMTP_MAIL_FROM_VARS);
        let rcpt_vars = TokenMap::default().with_variables(SMTP_RCPT_TO_VARS);

        Self {
            submitter: IfBlock::try_parse(
                config,
                "report.submitter",
                &TokenMap::default().with_variables(RCPT_DOMAIN_VARS),
            )
            .unwrap_or_else(|| {
                IfBlock::new::<()>("report.submitter", [], "key_get('default', 'hostname')")
            }),
            analysis: ReportAnalysis {
                addresses: config
                    .properties::<AddressMatch>("report.analysis.addresses")
                    .into_iter()
                    .map(|(_, m)| m)
                    .collect(),
                forward: config.property("report.analysis.forward").unwrap_or(true),
                store: config
                    .property_or_default::<Option<Duration>>("report.analysis.store", "30d")
                    .unwrap_or_default(),
            },
            dkim: Report::parse(config, "dkim", &rcpt_vars),
            spf: Report::parse(config, "spf", &sender_vars),
            dmarc: Report::parse(config, "dmarc", &rcpt_vars),
            dmarc_aggregate: AggregateReport::parse(
                config,
                "dmarc",
                &rcpt_vars.with_constants::<AggregateFrequency>(),
            ),
            tls: AggregateReport::parse(
                config,
                "tls",
                &TokenMap::default()
                    .with_variables(SMTP_QUEUE_HOST_VARS)
                    .with_constants::<AggregateFrequency>(),
            ),
        }
    }
}

impl Report {
    pub fn parse(config: &mut Config, id: &str, token_map: &TokenMap) -> Self {
        let mut report = Self {
            name: IfBlock::new::<()>(format!("report.{id}.from-name"), [], "'Report Subsystem'"),
            address: IfBlock::new::<()>(
                format!("report.{id}.from-address"),
                [],
                format!("'noreply-{id}@' + key_get('default', 'domain')"),
            ),
            subject: IfBlock::new::<()>(
                format!("report.{id}.subject"),
                [],
                format!(
                    "'{} Authentication Failure Report'",
                    id.to_ascii_uppercase()
                ),
            ),
            sign: IfBlock::new::<()>(
                format!("report.{id}.sign"),
                [],
                "['rsa-' + key_get('default', 'domain'), 'ed25519-' + key_get('default', 'domain')]",
            ),
            send: IfBlock::new::<()>(format!("report.{id}.send"), [], "[1, 1d]"),
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
    pub fn parse(config: &mut Config, id: &str, token_map: &TokenMap) -> Self {
        let rcpt_vars = TokenMap::default().with_variables(RCPT_DOMAIN_VARS);

        let mut report = Self {
            name: IfBlock::new::<()>(
                format!("report.{id}.aggregate.from-name"),
                [],
                format!("'{} Aggregate Report'", id.to_ascii_uppercase()),
            ),
            address: IfBlock::new::<()>(
                format!("report.{id}.aggregate.from-address"),
                [],
                format!("'noreply-{id}@' + key_get('default', 'domain')"),
            ),
            org_name: IfBlock::new::<()>(
                format!("report.{id}.aggregate.org-name"),
                [],
                "key_get('default', 'domain')",
            ),
            contact_info: IfBlock::empty(format!("report.{id}.aggregate.contact-info")),
            send: IfBlock::new::<AggregateFrequency>(
                format!("report.{id}.aggregate.send"),
                [],
                "daily",
            ),
            sign: IfBlock::new::<()>(
                format!("report.{id}.aggregate.sign"),
                [],
                "['rsa-' + key_get('default', 'domain'), 'ed25519-' + key_get('default', 'domain')]",
            ),
            max_size: IfBlock::new::<()>(format!("report.{id}.aggregate.max-size"), [], "26214400"),
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
        Self::parse(&mut Config::default())
    }
}

impl ParseValue for AggregateFrequency {
    fn parse_value(value: &str) -> Result<Self, String> {
        match value {
            "daily" | "day" => Ok(AggregateFrequency::Daily),
            "hourly" | "hour" => Ok(AggregateFrequency::Hourly),
            "weekly" | "week" => Ok(AggregateFrequency::Weekly),
            "never" | "disable" | "false" => Ok(AggregateFrequency::Never),
            _ => Err(format!("Invalid aggregate frequency value {:?}.", value,)),
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
    fn parse_value(value: &str) -> Result<Self, String> {
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
        Err(format!("Invalid address match value {:?}.", value,))
    }
}
