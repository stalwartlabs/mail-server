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

use super::{
    if_block::ConfigIf, AddressMatch, AggregateFrequency, AggregateReport, ConfigContext,
    EnvelopeKey, IfBlock, Report, ReportAnalysis, ReportConfig,
};
use utils::config::{
    utils::{AsKey, ParseValue},
    Config, DynValue,
};

pub trait ConfigReport {
    fn parse_reports(&self, ctx: &ConfigContext) -> super::Result<ReportConfig>;
    fn parse_report(
        &self,
        ctx: &ConfigContext,
        id: &str,
        default_hostname: &str,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<Report>;
    fn parse_aggregate_report(
        &self,
        ctx: &ConfigContext,
        id: &str,
        default_hostname: &str,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<AggregateReport>;
}

impl ConfigReport for Config {
    fn parse_reports(&self, ctx: &ConfigContext) -> super::Result<ReportConfig> {
        let sender_envelope_keys = [
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
            EnvelopeKey::AuthenticatedAs,
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
        ];
        let rcpt_envelope_keys = [
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
            EnvelopeKey::RecipientDomain,
        ];
        let mut addresses = Vec::new();
        for address in self.properties::<AddressMatch>("report.analysis.addresses") {
            addresses.push(address?.1);
        }

        let default_hostname = self.value_require("server.hostname")?;
        Ok(ReportConfig {
            dkim: self.parse_report(ctx, "dkim", default_hostname, &sender_envelope_keys)?,
            spf: self.parse_report(ctx, "spf", default_hostname, &sender_envelope_keys)?,
            dmarc: self.parse_report(ctx, "dmarc", default_hostname, &sender_envelope_keys)?,
            dmarc_aggregate: self.parse_aggregate_report(
                ctx,
                "dmarc",
                default_hostname,
                &sender_envelope_keys,
            )?,
            tls: self.parse_aggregate_report(ctx, "tls", default_hostname, &rcpt_envelope_keys)?,
            path: self
                .parse_if_block("report.path", ctx, &sender_envelope_keys)?
                .ok_or("Missing \"report.path\" property.")?,
            submitter: self
                .parse_if_block("report.submitter", ctx, &[EnvelopeKey::RecipientDomain])?
                .unwrap_or_else(|| IfBlock::new(default_hostname.to_string())),
            hash: self
                .parse_if_block("report.hash", ctx, &sender_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(32)),
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
        ctx: &ConfigContext,
        id: &str,
        default_hostname: &str,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<Report> {
        Ok(Report {
            name: self
                .parse_if_block(("report", id, "from-name"), ctx, available_keys)?
                .unwrap_or_else(|| IfBlock::new("Mail Delivery Subsystem".to_string())),
            address: self
                .parse_if_block(("report", id, "from-address"), ctx, available_keys)?
                .unwrap_or_else(|| IfBlock::new(format!("MAILER-DAEMON@{default_hostname}"))),
            subject: self
                .parse_if_block(("report", id, "subject"), ctx, available_keys)?
                .unwrap_or_else(|| IfBlock::new(format!("{} Report", id.to_ascii_uppercase()))),
            sign: self
                .parse_if_block::<Vec<DynValue>>(("report", id, "sign"), ctx, available_keys)?
                .unwrap_or_default()
                .map_if_block(&ctx.signers, &("report", id, "sign").as_key(), "signature")?,
            send: self
                .parse_if_block(("report", id, "send"), ctx, available_keys)?
                .unwrap_or_default(),
        })
    }

    fn parse_aggregate_report(
        &self,
        ctx: &ConfigContext,
        id: &str,
        default_hostname: &str,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<AggregateReport> {
        let rcpt_envelope_keys = [EnvelopeKey::RecipientDomain];

        Ok(AggregateReport {
            name: self
                .parse_if_block(
                    ("report", id, "aggregate.from-name"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
                .unwrap_or_else(|| {
                    IfBlock::new(format!("{} Aggregate Report", id.to_ascii_uppercase()))
                }),
            address: self
                .parse_if_block(
                    ("report", id, "aggregate.from-address"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
                .unwrap_or_else(|| IfBlock::new(format!("noreply-{id}@{default_hostname}"))),
            org_name: self
                .parse_if_block(
                    ("report", id, "aggregate.org-name"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
                .unwrap_or_default(),
            contact_info: self
                .parse_if_block(
                    ("report", id, "aggregate.contact-info"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
                .unwrap_or_default(),
            send: self
                .parse_if_block(("report", id, "aggregate.send"), ctx, available_keys)?
                .unwrap_or_default(),
            sign: self
                .parse_if_block::<Vec<DynValue>>(
                    ("report", id, "aggregate.sign"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
                .unwrap_or_default()
                .map_if_block(
                    &ctx.signers,
                    &("report", id, "aggregate.sign").as_key(),
                    "signature",
                )?,
            max_size: self
                .parse_if_block(
                    ("report", id, "aggregate.max-size"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
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
