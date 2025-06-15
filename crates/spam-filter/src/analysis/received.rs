/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::Server;
use mail_parser::{HeaderName, Host};

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeReceived: Sync + Send {
    fn spam_filter_analyze_received(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeReceived for Server {
    async fn spam_filter_analyze_received(&self, ctx: &mut SpamFilterContext<'_>) {
        let mut rcvd_count = 0;
        let mut rcvd_from_ip = 0;
        let mut tls_count = 0;

        for header in ctx.input.message.headers() {
            if let HeaderName::Received = &header.name {
                if !ctx
                    .input
                    .message
                    .raw_message()
                    .get(header.offset_start as usize..header.offset_end as usize)
                    .unwrap_or_default()
                    .is_ascii()
                {
                    // Received headers have non-ASCII characters
                    ctx.result.add_tag("RCVD_ILLEGAL_CHARS");
                }

                if let Some(received) = header.value().as_received() {
                    let helo_domain = received.from().or_else(|| received.helo());
                    let ip_rev = received.from_iprev();

                    if matches!(&helo_domain, Some(Host::Name(hostname)) if hostname.eq_ignore_ascii_case("user"))
                    {
                        // HELO domain is "user"
                        ctx.result.add_tag("RCVD_HELO_USER");
                    } else if let (Some(Host::Name(helo_domain)), Some(ip_rev)) =
                        (helo_domain, ip_rev)
                    {
                        if helo_domain.to_lowercase() != ip_rev.to_lowercase() {
                            // HELO domain does not match PTR record
                            ctx.result.add_tag("FORGED_RCVD_TRAIL");
                        }
                    }

                    if let Some(delivered_for) = received.for_().map(|s| s.to_lowercase()) {
                        if ctx
                            .output
                            .all_recipients()
                            .any(|r| r.email.address == delivered_for)
                        {
                            // Recipient appears on Received trail
                            ctx.result.add_tag("PREVIOUSLY_DELIVERED");
                        }
                    }

                    if matches!(received.from, Some(Host::IpAddr(_))) {
                        // Received from an IP address rather than a FQDN
                        rcvd_from_ip += 1;
                    }

                    if received.tls_version().is_some() {
                        // Received with TLS
                        tls_count += 1;
                    }
                } else {
                    // Received header is not RFC 5322 compliant
                    ctx.result.add_tag("RCVD_UNPARSABLE");
                }

                rcvd_count += 1;
            }
        }

        if rcvd_from_ip >= 2 || (rcvd_from_ip == 1 && ctx.output.ehlo_host.ip.is_some()) {
            // Has two or more Received headers containing bare IP addresses
            ctx.result.add_tag("RCVD_DOUBLE_IP_SPAM");
        }

        // Received from an authenticated user
        if ctx.input.authenticated_as.is_some() {
            ctx.result.add_tag("RCVD_VIA_SMTP_AUTH");
        }

        // Received with TLS checks
        if rcvd_count > 0 && rcvd_count == tls_count && ctx.input.is_tls {
            ctx.result.add_tag("RCVD_TLS_ALL");
        } else if ctx.input.is_tls {
            ctx.result.add_tag("RCVD_TLS_LAST");
        } else {
            ctx.result.add_tag("RCVD_NO_TLS_LAST");
        }

        match rcvd_count {
            0 => {
                ctx.result.add_tag("RCVD_COUNT_ZERO");
            }
            1 => {
                ctx.result.add_tag("RCVD_COUNT_ONE");
            }
            2 => {
                ctx.result.add_tag("RCVD_COUNT_TWO");
            }
            3 => {
                ctx.result.add_tag("RCVD_COUNT_THREE");
            }
            4 | 5 => {
                ctx.result.add_tag("RCVD_COUNT_FIVE");
            }
            6 | 7 => {
                ctx.result.add_tag("RCVD_COUNT_SEVEN");
            }
            8..=12 => {
                ctx.result.add_tag("RCVD_COUNT_TWELVE");
            }
            _ => {}
        }
    }
}
