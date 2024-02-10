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

use crate::core::eval::*;
use utils::{
    config::{
        if_block::IfBlock,
        utils::{AsKey, ConstantValue, NoConstants, ParseValue},
        Config,
    },
    expr::{Constant, Variable},
};

use super::{
    map_expr_token, AddressMatch, AggregateFrequency, AggregateReport, Report, ReportAnalysis,
    ReportConfig,
};

pub trait ConfigReport {
    fn parse_reports(&self) -> super::Result<ReportConfig>;
    fn parse_report(
        &self,
        id: &str,
        default_hostname: &str,
        available_keys: &[u32],
    ) -> super::Result<Report>;
    fn parse_aggregate_report(
        &self,
        id: &str,
        default_hostname: &str,
        available_keys: &[u32],
    ) -> super::Result<AggregateReport>;
}

impl ConfigReport for Config {
    fn parse_reports(&self) -> super::Result<ReportConfig> {
        let sender_envelope_keys = &[
            V_SENDER,
            V_SENDER_DOMAIN,
            V_PRIORITY,
            V_AUTHENTICATED_AS,
            V_LISTENER,
            V_REMOTE_IP,
            V_LOCAL_IP,
        ];
        let rcpt_envelope_keys = &[
            V_SENDER,
            V_SENDER_DOMAIN,
            V_PRIORITY,
            V_REMOTE_IP,
            V_LOCAL_IP,
            V_RECIPIENT_DOMAIN,
        ];
        let mut addresses = Vec::new();
        for address in self.properties::<AddressMatch>("report.analysis.addresses") {
            addresses.push(address?.1);
        }

        let default_hostname = self.value_require("server.hostname")?;
        Ok(ReportConfig {
            dkim: self.parse_report("dkim", default_hostname, sender_envelope_keys)?,
            spf: self.parse_report("spf", default_hostname, sender_envelope_keys)?,
            dmarc: self.parse_report("dmarc", default_hostname, sender_envelope_keys)?,
            dmarc_aggregate: self.parse_aggregate_report(
                "dmarc",
                default_hostname,
                sender_envelope_keys,
            )?,
            tls: self.parse_aggregate_report("tls", default_hostname, rcpt_envelope_keys)?,
            submitter: self
                .parse_if_block("report.submitter", |name| {
                    map_expr_token::<NoConstants>(name, &[V_RECIPIENT_DOMAIN])
                })?
                .unwrap_or_else(|| IfBlock::new(default_hostname.to_string())),
            analysis: ReportAnalysis {
                addresses,
                forward: self.property("report.analysis.forward")?.unwrap_or(false),
                store: self.property("report.analysis.store")?,
                report_id: 0.into(),
            },
        })
    }

    fn parse_report(
        &self,
        id: &str,
        default_hostname: &str,
        available_keys: &[u32],
    ) -> super::Result<Report> {
        Ok(Report {
            name: self
                .parse_if_block(("report", id, "from-name"), |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new("Mail Delivery Subsystem".to_string())),
            address: self
                .parse_if_block(("report", id, "from-address"), |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(format!("MAILER-DAEMON@{default_hostname}"))),
            subject: self
                .parse_if_block(("report", id, "subject"), |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(format!("{} Report", id.to_ascii_uppercase()))),
            sign: self
                .parse_if_block(("report", id, "sign"), |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_default(),
            send: self
                .parse_if_block(("report", id, "send"), |name| {
                    map_expr_token::<Duration>(name, available_keys)
                })?
                .unwrap_or_default(),
        })
    }

    fn parse_aggregate_report(
        &self,
        id: &str,
        default_hostname: &str,
        available_keys: &[u32],
    ) -> super::Result<AggregateReport> {
        let rcpt_envelope_keys = &[V_RECIPIENT_DOMAIN];

        Ok(AggregateReport {
            name: self
                .parse_if_block(("report", id, "aggregate.from-name"), |name| {
                    map_expr_token::<NoConstants>(name, rcpt_envelope_keys)
                })?
                .unwrap_or_else(|| {
                    IfBlock::new(format!("{} Aggregate Report", id.to_ascii_uppercase()))
                }),
            address: self
                .parse_if_block(("report", id, "aggregate.from-address"), |name| {
                    map_expr_token::<NoConstants>(name, rcpt_envelope_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(format!("noreply-{id}@{default_hostname}"))),
            org_name: self
                .parse_if_block(("report", id, "aggregate.org-name"), |name| {
                    map_expr_token::<NoConstants>(name, rcpt_envelope_keys)
                })?
                .unwrap_or_default(),
            contact_info: self
                .parse_if_block(("report", id, "aggregate.contact-info"), |name| {
                    map_expr_token::<NoConstants>(name, rcpt_envelope_keys)
                })?
                .unwrap_or_default(),
            send: self
                .parse_if_block(("report", id, "aggregate.send"), |name| {
                    map_expr_token::<AggregateFrequency>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(AggregateFrequency::Never)),
            sign: self
                .parse_if_block(("report", id, "aggregate.sign"), |name| {
                    map_expr_token::<NoConstants>(name, rcpt_envelope_keys)
                })?
                .unwrap_or_default(),
            max_size: self
                .parse_if_block(("report", id, "aggregate.max-size"), |name| {
                    map_expr_token::<NoConstants>(name, rcpt_envelope_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(25 * 1024 * 1024)),
        })
    }
}

impl ParseValue for AggregateFrequency {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
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

impl ParseValue for AddressMatch {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
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
