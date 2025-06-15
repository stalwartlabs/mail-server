/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, future::Future};

use common::{
    Server,
    config::spamfilter::{Element, IpResolver, Location},
};
use mail_auth::IprevResult;
use mail_parser::{HeaderName, HeaderValue, Host};
use nlp::tokenizers::types::TokenType;
use store::ahash::AHashSet;

use crate::{IpParts, SpamFilterContext, TextPart, modules::dnsbl::check_dnsbl};

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
        let mut ips = AHashSet::new();

        ips.insert(ElementLocation::new(ctx.input.remote_ip, Location::Tcp));

        // Obtain IP addresses from Received headers
        for header in ctx.input.message.headers() {
            if let (HeaderName::Received, HeaderValue::Received(received)) =
                (&header.name, &header.value)
            {
                if let Some(ip) = received.from_ip() {
                    if !ip.is_loopback() && !self.is_ip_allowed(&ip) {
                        ips.insert(ElementLocation::new(ip, Location::HeaderReceived));
                    }
                }
                for host in [&received.from, &received.helo, &received.by]
                    .into_iter()
                    .flatten()
                {
                    if let Host::IpAddr(ip) = host {
                        if !ip.is_loopback() && !self.is_ip_allowed(ip) {
                            ips.insert(ElementLocation::new(*ip, Location::HeaderReceived));
                        }
                    }
                }
            }
        }

        // Obtain IP addresses from the message body
        for (part_id, part) in ctx.output.text_parts.iter().enumerate() {
            let part_id = part_id as u32;
            let is_body = ctx.input.message.text_body.contains(&part_id)
                || ctx.input.message.html_body.contains(&part_id);
            match part {
                TextPart::Plain { tokens, .. } | TextPart::Html { tokens, .. } => {
                    ips.extend(tokens.iter().filter_map(|t| {
                        if let TokenType::IpAddr(ip) = t {
                            ip.ip.map(|ip| {
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

                TextPart::None => (),
            }
        }

        // Validate IP addresses
        for ip in &ips {
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

            check_dnsbl(
                self,
                ctx,
                &IpResolver::new(ip.element),
                Element::Ip,
                ip.location,
            )
            .await;
        }
        ctx.output.ips = ips;

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

impl<'x> IpParts<'x> {
    pub fn new(text: impl Into<Cow<'x, str>>) -> IpParts<'x> {
        let text = text.into();
        IpParts {
            ip: text.parse().ok(),
            text,
        }
    }
}
