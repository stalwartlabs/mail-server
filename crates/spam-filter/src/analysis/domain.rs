/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::HashSet, future::Future};

use common::{
    config::spamfilter::{Element, Location},
    Server,
};
use mail_auth::DkimResult;
use mail_parser::{HeaderName, HeaderValue, Host};
use nlp::tokenizers::types::TokenType;

use crate::{
    modules::{
        dnsbl::is_dnsbl,
        expression::{SpamFilterResolver, StringResolver},
        html::{HtmlToken, A, HREF},
    },
    Email, Hostname, Recipient, SpamFilterContext, TextPart,
};

use super::{is_trusted_domain, ElementLocation};

pub trait SpamFilterAnalyzeDomain: Sync + Send {
    fn spam_filter_analyze_domain(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeDomain for Server {
    async fn spam_filter_analyze_domain(&self, ctx: &mut SpamFilterContext<'_>) {
        // Obtain email addresses and domains
        let mut domains: HashSet<ElementLocation<String>> = HashSet::new();
        let mut emails: HashSet<ElementLocation<Recipient>> = HashSet::new();

        // Add DKIM domains
        for dkim in ctx.input.dkim_result {
            if dkim.result() == &DkimResult::Pass {
                if let Some(domain) = dkim.signature().map(|s| &s.d) {
                    domains.insert(ElementLocation::new(
                        domain.to_lowercase(),
                        Location::HeaderDkimPass,
                    ));
                }
            }
        }

        // Add Received headers
        for header in ctx.input.message.headers() {
            if let (HeaderName::Received, HeaderValue::Received(received)) =
                (&header.name, &header.value)
            {
                for host in [&received.from, &received.helo, &received.by]
                    .into_iter()
                    .flatten()
                {
                    if let Host::Name(name) = host {
                        if let Some(name) = Hostname::new(name.as_ref()).sld {
                            domains.insert(ElementLocation::new(name, Location::HeaderReceived));
                        }
                    }
                }
            }
        }

        // Add EHLO domain
        if !ctx.output.ehlo_host.fqdn.is_empty() {
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
            let is_body = ctx.input.message.text_body.contains(&part_id)
                || ctx.input.message.html_body.contains(&part_id);
            match part {
                TextPart::Plain { tokens, .. } => emails.extend(tokens.iter().filter_map(|t| {
                    if let TokenType::Email(email) = t {
                        Some(ElementLocation::new(
                            Recipient {
                                email: Email::new(email),
                                name: None,
                            },
                            if is_body {
                                Location::BodyText
                            } else {
                                Location::Attachment
                            },
                        ))
                    } else {
                        None
                    }
                })),
                TextPart::Html {
                    tokens,
                    html_tokens,
                    ..
                } => {
                    emails.extend(tokens.iter().filter_map(|t| {
                        if let TokenType::Email(email) = t {
                            Some(ElementLocation::new(
                                Recipient {
                                    email: Email::new(email),
                                    name: None,
                                },
                                if is_body {
                                    Location::BodyHtml
                                } else {
                                    Location::Attachment
                                },
                            ))
                        } else {
                            None
                        }
                    }));
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
                                    if value.contains('@') {
                                        return Some(ElementLocation::new(
                                            Recipient {
                                                email: Email::new(value),
                                                name: None,
                                            },
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
                }
                TextPart::None => (),
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
            if ctx.result.rbl_email_checks < self.core.spam.dnsbl.max_email_checks {
                for dnsbl in &self.core.spam.dnsbl.servers {
                    if dnsbl.scope == Element::Email {
                        if let Some(tag) = is_dnsbl(
                            self,
                            dnsbl,
                            SpamFilterResolver::new(ctx, &email.element, email.location),
                        )
                        .await
                        {
                            ctx.result.add_tag(tag);
                        }
                    }
                }
                ctx.result.rbl_email_checks += 1;
            }

            domains.insert(ElementLocation::new(
                email.element.email.domain_part.fqdn.clone(),
                email.location,
            ));
        }

        // Validate domains
        for domain in &domains {
            // Skip trusted domains
            if is_trusted_domain(self, &domain.element, ctx.input.span_id).await {
                continue;
            }

            // Check Domain DNSBL
            if ctx.result.rbl_domain_checks < self.core.spam.dnsbl.max_domain_checks {
                for dnsbl in &self.core.spam.dnsbl.servers {
                    if dnsbl.scope == Element::Domain {
                        if let Some(tag) = is_dnsbl(
                            self,
                            dnsbl,
                            SpamFilterResolver::new(
                                ctx,
                                &StringResolver(domain.element.as_str()),
                                domain.location,
                            ),
                        )
                        .await
                        {
                            ctx.result.add_tag(tag);
                        }
                    }
                }
                ctx.result.rbl_domain_checks += 1;
            }
        }
        ctx.output.emails = emails;
        ctx.output.domains = domains;
    }
}
