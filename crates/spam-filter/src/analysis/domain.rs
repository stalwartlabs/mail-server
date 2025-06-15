/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::HashSet, future::Future};

use common::{
    Server,
    config::spamfilter::{Element, Location},
};
use compact_str::CompactString;
use mail_auth::DkimResult;
use mail_parser::{HeaderName, HeaderValue, Host, parsers::MessageStream};
use nlp::tokenizers::types::TokenType;

use crate::{
    Email, Hostname, Recipient, SpamFilterContext, TextPart,
    modules::{
        dnsbl::check_dnsbl,
        expression::StringResolver,
        html::{A, HREF, HtmlToken},
    },
};

use super::{ElementLocation, is_trusted_domain};

pub trait SpamFilterAnalyzeDomain: Sync + Send {
    fn spam_filter_analyze_domain(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeDomain for Server {
    async fn spam_filter_analyze_domain(&self, ctx: &mut SpamFilterContext<'_>) {
        // Obtain email addresses and domains
        let mut domains: HashSet<ElementLocation<CompactString>> = HashSet::new();
        let mut emails: HashSet<ElementLocation<Recipient>> = HashSet::new();

        // Add DKIM domains
        for dkim in ctx.input.dkim_result {
            if dkim.result() == &DkimResult::Pass {
                if let Some(domain) = dkim.signature().map(|s| &s.d) {
                    domains.insert(ElementLocation::new(
                        CompactString::from_str_to_lowercase(domain),
                        Location::HeaderDkimPass,
                    ));
                }
            }
        }

        // Add Received headers
        for header in ctx.input.message.headers() {
            match (&header.name, &header.value) {
                (HeaderName::Received, HeaderValue::Received(received)) => {
                    for host in [&received.from, &received.helo, &received.by]
                        .into_iter()
                        .flatten()
                    {
                        if let Host::Name(name) = host {
                            if let Some(name) = Hostname::new(name.as_ref()).sld {
                                domains
                                    .insert(ElementLocation::new(name, Location::HeaderReceived));
                            }
                        }
                    }
                }
                (HeaderName::MessageId, value) => {
                    if let Some(mid_domain) = value
                        .as_text()
                        .and_then(|s| s.rsplit_once('@'))
                        .and_then(|(_, d)| {
                            let host = Hostname::new(d);
                            if host.sld.is_some() { Some(host) } else { None }
                        })
                    {
                        domains.insert(ElementLocation::new(mid_domain.fqdn, Location::HeaderMid));
                    }
                }
                (HeaderName::Other(name), _)
                    if name.eq_ignore_ascii_case("Disposition-Notification-To") =>
                {
                    if let Some(address) = MessageStream::new(
                        ctx.input
                            .message
                            .raw_message
                            .get(header.offset_start as usize..header.offset_end as usize)
                            .unwrap_or_default(),
                    )
                    .parse_address()
                    .as_address()
                    {
                        for addr in address.iter() {
                            if let Some(email) = addr.address() {
                                emails.insert(ElementLocation::new(
                                    Recipient {
                                        email: Email::new(email),
                                        name: None,
                                    },
                                    Location::HeaderDnt,
                                ));
                            }
                        }
                    }
                }
                _ => (),
            }
        }

        // Add EHLO domain
        if ctx.output.ehlo_host.sld.is_some() {
            domains.insert(ElementLocation::new(
                ctx.output.ehlo_host.fqdn.clone(),
                Location::Ehlo,
            ));
        }

        // Add PTR
        if let Some(ptr) = &ctx.output.iprev_ptr {
            domains.insert(ElementLocation::new(ptr.clone(), Location::Tcp));
        }

        // Add From, Envelope From and Reply-To
        emails.insert(ElementLocation::new(
            ctx.output.from.clone(),
            Location::HeaderFrom,
        ));
        if let Some(reply_to) = &ctx.output.reply_to {
            emails.insert(ElementLocation::new(
                reply_to.clone(),
                Location::HeaderReplyTo,
            ));
        }
        emails.insert(ElementLocation::new(
            Recipient {
                email: ctx.output.env_from_addr.clone(),
                name: None,
            },
            Location::EnvelopeFrom,
        ));

        // Add emails found in the message
        for (part_id, part) in ctx.output.text_parts.iter().enumerate() {
            let part_id = part_id as u32;
            let is_body = ctx.input.message.text_body.contains(&part_id)
                || ctx.input.message.html_body.contains(&part_id);
            let tokens = match part {
                TextPart::Plain { tokens, .. } => tokens,
                TextPart::Html {
                    tokens,
                    html_tokens,
                    ..
                } => {
                    emails.extend(html_tokens.iter().filter_map(|token| {
                        if let HtmlToken::StartTag {
                            name: A,
                            attributes,
                            ..
                        } = token
                        {
                            attributes.iter().find_map(|(attr, value)| {
                                if *attr == HREF {
                                    let value = value.as_deref()?.strip_prefix("mailto:")?;
                                    let email =
                                        Email::new(value.split_once('?').map_or(value, |(e, _)| e));

                                    if email.is_valid() {
                                        return Some(ElementLocation::new(
                                            Recipient { email, name: None },
                                            if is_body {
                                                Location::BodyHtml
                                            } else {
                                                Location::Attachment
                                            },
                                        ));
                                    }
                                }
                                None
                            })
                        } else {
                            None
                        }
                    }));
                    tokens
                }
                TextPart::None => continue,
            };

            for token in tokens {
                if let TokenType::Email(email) = token {
                    if is_body && !ctx.result.has_tag("RCPT_IN_BODY") {
                        for rcpt in ctx.output.all_recipients() {
                            if rcpt.email.address == email.address {
                                ctx.result.add_tag("RCPT_IN_BODY");
                                break;
                            }
                        }
                    }

                    if email.is_valid() {
                        emails.insert(ElementLocation::new(
                            Recipient {
                                email: email.clone(),
                                name: None,
                            },
                            if is_body {
                                Location::BodyText
                            } else {
                                Location::Attachment
                            },
                        ));
                    }
                }
            }
        }

        // Validate email
        for email in &emails {
            // Skip trusted domains
            if !email.element.email.is_valid()
                || is_trusted_domain(
                    self,
                    &email.element.email.domain_part.fqdn,
                    ctx.input.span_id,
                )
                .await
            {
                continue;
            }

            // Check Email DNSBL
            check_dnsbl(self, ctx, &email.element, Element::Email, email.location).await;

            domains.insert(ElementLocation::new(
                email.element.email.domain_part.fqdn.clone(),
                email.location,
            ));
        }

        // Validate domains
        for domain in &domains {
            // Skip trusted domains
            if !is_trusted_domain(self, &domain.element, ctx.input.span_id).await {
                // Check Domain DNSBL
                check_dnsbl(
                    self,
                    ctx,
                    &StringResolver(domain.element.as_str()),
                    Element::Domain,
                    domain.location,
                )
                .await;
            }
        }
        ctx.output.emails = emails;
        ctx.output.domains = domains;
    }
}
