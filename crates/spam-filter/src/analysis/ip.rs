/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{future::Future, net::IpAddr};

use common::{
    config::spamfilter::{Element, IpResolver, Location},
    Server,
};
use mail_auth::IprevResult;
use mail_parser::{HeaderName, HeaderValue, Host};
use nlp::tokenizers::types::TokenType;

use crate::{
    modules::{dnsbl::is_dnsbl, expression::SpamFilterResolver},
    SpamFilterContext, TextPart,
};

use super::ElementLocation;

pub trait SpamFilterAnalyzeIp: Sync + Send {
    fn spam_filter_analyze_ip(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeIp for Server {
    async fn spam_filter_analyze_ip(&self, ctx: &mut SpamFilterContext<'_>) {
        // IP Address RBL
        ctx.output
            .ips
            .insert(ElementLocation::new(ctx.input.remote_ip, Location::Tcp));

        // Obtain IP addresses from Received headers
        for header in ctx.input.message.headers() {
            if let (HeaderName::Received, HeaderValue::Received(received)) =
                (&header.name, &header.value)
            {
                if let Some(ip) = received.from_ip() {
                    if !ip.is_loopback() && !self.is_ip_allowed(&ip) {
                        ctx.output
                            .ips
                            .insert(ElementLocation::new(ip, Location::HeaderReceived));
                    }
                }
                for host in [&received.from, &received.helo, &received.by]
                    .into_iter()
                    .flatten()
                {
                    if let Host::IpAddr(ip) = host {
                        if !ip.is_loopback() && !self.is_ip_allowed(ip) {
                            ctx.output
                                .ips
                                .insert(ElementLocation::new(*ip, Location::HeaderReceived));
                        }
                    }
                }
            }
        }

        // Obtain IP addresses from the message body
        for (part_id, part) in ctx.output.text_parts.iter().enumerate() {
            let is_body = ctx.input.message.text_body.contains(&part_id)
                || ctx.input.message.html_body.contains(&part_id);
            match part {
                TextPart::Plain { tokens, .. } => {
                    ctx.output.ips.extend(tokens.iter().filter_map(|t| {
                        if let TokenType::IpAddr(ip) = t {
                            ip.parse::<IpAddr>().ok().map(|ip| {
                                ElementLocation::new(
                                    ip,
                                    if is_body {
                                        Location::BodyText
                                    } else {
                                        Location::Attachment
                                    },
                                )
                            })
                        } else {
                            None
                        }
                    }))
                }
                TextPart::Html { tokens, .. } => {
                    ctx.output.ips.extend(tokens.iter().filter_map(|t| {
                        if let TokenType::IpAddr(ip) = t {
                            ip.parse::<IpAddr>().ok().map(|ip| {
                                ElementLocation::new(
                                    ip,
                                    if is_body {
                                        Location::BodyHtml
                                    } else {
                                        Location::Attachment
                                    },
                                )
                            })
                        } else {
                            None
                        }
                    }))
                }
                TextPart::None => (),
            }
        }

        // Validate IP addresses
        for ip in &ctx.output.ips {
            if ip.element.is_loopback()
                || ip.element.is_multicast()
                || ip.element.is_unspecified()
                || self.is_ip_allowed(&ip.element)
            {
                continue;
            } else if self.is_ip_blocked(&ip.element) {
                ctx.result.add_tag("IP_BLOCKED");
                continue;
            }

            let ip_resolver = IpResolver::new(ip.element);
            for dnsbl in &self.core.spam.dnsbl.servers {
                if dnsbl.scope == Element::Ip {
                    if let Some(tag) = is_dnsbl(
                        self,
                        dnsbl,
                        SpamFilterResolver::new(ctx, &ip_resolver, ip.location),
                    )
                    .await
                    {
                        ctx.result.add_tag(tag);
                    }
                }
            }
            ctx.result.rbl_ip_checks += 1;
            if ctx.result.rbl_ip_checks >= self.core.spam.dnsbl.max_ip_checks {
                break;
            }
        }

        // Reverse DNS validation
        if let Some(iprev) = ctx.input.iprev_result {
            match &iprev.result {
                IprevResult::TempError(_) => ctx.result.add_tag("RDNS_DNSFAIL"),
                IprevResult::Fail(_) | IprevResult::PermError(_) => ctx.result.add_tag("RDNS_NONE"),
                IprevResult::Pass | IprevResult::None => (),
            }
        }
    }
}
