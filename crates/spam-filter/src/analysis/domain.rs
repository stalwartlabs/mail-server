use std::{collections::HashSet, future::Future};

use common::{
    config::spamfilter::{Element, Location},
    expr::{functions::ResolveVariable, Variable},
    Server,
};
use mail_auth::DkimResult;
use mail_parser::HeaderName;
use nlp::tokenizers::types::TokenType;

use crate::{modules::dnsbl::is_dnsbl, Email, Recipient, SpamFilterContext, TextPart};

use super::{is_trusted_domain, ElementLocation, SpamFilterResolver};

pub trait SpamFilterAnalyzeDomain: Sync + Send {
    fn spam_filter_analyze_domain(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeDomain for Server {
    async fn spam_filter_analyze_domain(&self, ctx: &mut SpamFilterContext<'_>) {
        // Obtain email addresses and domains
        let mut domains = HashSet::new();
        let mut emails = HashSet::new();

        // Add DKIM domains
        for dkim in ctx.input.dkim_result {
            if dkim.result() == &DkimResult::Pass {
                if let Some(domain) = dkim.signature().map(|s| &s.d) {
                    domains.insert(ElementLocation::new(
                        domain.to_lowercase(),
                        Location::DkimPassing,
                    ));
                }
            }
        }

        // Add EHLO domain
        domains.insert(ElementLocation::new(
            ctx.output.ehlo_host.fqdn.to_string(),
            Location::Ehlo,
        ));

        // Add PTR
        if let Some(ptr) = &ctx.output.iprev_ptr {
            domains.insert(ElementLocation::new(ptr.clone(), Location::Tcp));
        }

        // Add From, Envelope From and Reply-To
        emails.insert(ElementLocation::new(
            ctx.output.from.clone(),
            HeaderName::From,
        ));
        if let Some(reply_to) = &ctx.output.reply_to {
            emails.insert(ElementLocation::new(reply_to.clone(), HeaderName::ReplyTo));
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
                TextPart::Html { tokens, .. } => emails.extend(tokens.iter().filter_map(|t| {
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
                })),
                TextPart::None => (),
            }
        }

        // Validate email
        for email in emails {
            // Skip trusted domains
            if is_trusted_domain(
                self,
                &email.element.email.domain_part.fqdn,
                ctx.input.span_id,
            )
            .await
            {
                continue;
            }

            // Check Email DNSBL
            if ctx.result.rbl_email_checks < self.core.spam.max_rbl_email_checks {
                for dnsbl in &self.core.spam.dnsbls {
                    if dnsbl.element == Element::Email
                        && dnsbl.element_location.contains(&email.location)
                    {
                        if let Some(tag) =
                            is_dnsbl(self, dnsbl, SpamFilterResolver::new(ctx, &email.element))
                                .await
                        {
                            ctx.result.add_tag(tag);
                        }
                    }
                }
                ctx.result.rbl_email_checks += 1;
            }

            domains.insert(ElementLocation::new(
                email.element.email.domain_part.fqdn,
                email.location,
            ));
        }

        // Validate domains
        for domain in domains {
            // Skip trusted domains
            if is_trusted_domain(self, &domain.element, ctx.input.span_id).await {
                continue;
            }

            // Check Domain DNSBL
            if ctx.result.rbl_domain_checks < self.core.spam.max_rbl_domain_checks {
                for dnsbl in &self.core.spam.dnsbls {
                    if dnsbl.element == Element::Domain
                        && dnsbl.element_location.contains(&domain.location)
                    {
                        if let Some(tag) = is_dnsbl(
                            self,
                            dnsbl,
                            SpamFilterResolver::new(ctx, &domain.element.as_str()),
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
    }
}

pub const V_RCPT_EMAIL: u32 = 0;
pub const V_RCPT_NAME: u32 = 1;
pub const V_RCPT_LOCAL: u32 = 2;
pub const V_RCPT_DOMAIN: u32 = 3;
pub const V_RCPT_DOMAIN_SLD: u32 = 4;

impl ResolveVariable for Recipient {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        match variable {
            V_RCPT_EMAIL => Variable::String(self.email.address.as_str().into()),
            V_RCPT_NAME => Variable::String(self.name.as_deref().unwrap_or_default().into()),
            V_RCPT_LOCAL => Variable::String(self.email.local_part.as_str().into()),
            V_RCPT_DOMAIN => Variable::String(self.email.domain_part.fqdn.as_str().into()),
            V_RCPT_DOMAIN_SLD => Variable::String(self.email.domain_part.sld_or_default().into()),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}
