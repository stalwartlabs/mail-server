/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::Server;
use mail_parser::HeaderName;

use crate::{Hostname, SpamFilterContext};

pub trait SpamFilterAnalyzeMid: Sync + Send {
    fn spam_filter_analyze_message_id(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeMid for Server {
    async fn spam_filter_analyze_message_id(&self, ctx: &mut SpamFilterContext<'_>) {
        let mut mid = "";
        let mut mid_raw = "";

        for header in ctx.input.message.headers() {
            if let (HeaderName::MessageId, value) = (&header.name, &header.value) {
                mid = value.as_text().unwrap_or_default();
                mid_raw = std::str::from_utf8(
                    &ctx.input.message.raw_message()
                        [header.offset_start as usize..header.offset_end as usize],
                )
                .unwrap_or_default()
                .trim();
                break;
            }
        }

        if !mid.is_empty() {
            let mid = mid.to_lowercase();
            if let Some(mid_host) = mid.rsplit_once('@').map(|(_, host)| Hostname::new(host)) {
                if mid_host.ip.is_some() {
                    if mid_host.fqdn.starts_with('[') {
                        ctx.result.add_tag("MID_RHS_IP_LITERAL");
                    } else {
                        ctx.result.add_tag("MID_BARE_IP");
                    }
                } else if !mid_host.fqdn.contains('.') {
                    ctx.result.add_tag("MID_RHS_NOT_FQDN");
                } else if mid_host.fqdn.starts_with("www.") {
                    ctx.result.add_tag("MID_RHS_WWW");
                }

                if !mid_raw.is_ascii() || mid_raw.contains('(') || mid.starts_with('@') {
                    ctx.result.add_tag("INVALID_MSGID");
                }

                if mid_host.fqdn.len() > 255 {
                    ctx.result.add_tag("MID_RHS_TOO_LONG");
                }

                // From address present in Message-ID checks
                for (part, sender) in [
                    ("FROM", &ctx.output.from.email),
                    ("ENV_FROM", &ctx.output.env_from_addr),
                ] {
                    if !sender.address.is_empty() {
                        if mid.contains(sender.address.as_str()) {
                            ctx.result.add_tag(format!("MID_CONTAINS_{part}"));
                        } else if mid_host.fqdn == sender.domain_part.fqdn {
                            ctx.result.add_tag(format!("MID_RHS_MATCH_{part}"));
                        } else if matches!((&mid_host.sld, &sender.domain_part.sld), (Some(mid_sld), Some(sender_sld)) if mid_sld == sender_sld)
                        {
                            ctx.result.add_tag(format!("MID_RHS_MATCH_{part}TLD"));
                        }
                    }
                }

                // To/Cc addresses present in Message-ID checks
                for rcpt in ctx.output.all_recipients() {
                    if mid.contains(rcpt.email.address.as_str()) {
                        ctx.result.add_tag("MID_CONTAINS_TO");
                    } else if mid_host.fqdn == rcpt.email.domain_part.fqdn {
                        ctx.result.add_tag("MID_RHS_MATCH_TO");
                    }
                }
            } else {
                ctx.result.add_tag("INVALID_MSGID");
            }

            if !mid_raw.starts_with('<') || !mid_raw.contains('>') {
                ctx.result.add_tag("MID_MISSING_BRACKETS");
            }
        } else {
            ctx.result.add_tag("MISSING_MID");
        }
    }
}
