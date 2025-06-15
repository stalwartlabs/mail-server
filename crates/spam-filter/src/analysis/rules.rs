/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::{
    Server,
    config::spamfilter::{IpResolver, Location},
};
use compact_str::CompactString;

use crate::{
    SpamFilterContext, TextPart,
    modules::expression::{EmailHeader, SpamFilterResolver, StringResolver},
};

pub trait SpamFilterAnalyzeRules: Sync + Send {
    fn spam_filter_analyze_rules(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeRules for Server {
    async fn spam_filter_analyze_rules(&self, ctx: &mut SpamFilterContext<'_>) {
        if !self.core.spam.rules.url.is_empty() {
            for url in &ctx.output.urls {
                for rule in &self.core.spam.rules.url {
                    if let Some(tag) = self
                        .eval_if::<CompactString, _>(
                            rule,
                            &SpamFilterResolver::new(ctx, &url.element, url.location),
                            ctx.input.span_id,
                        )
                        .await
                    {
                        ctx.result.tags.insert(tag);
                    }
                }
            }
        }

        if !self.core.spam.rules.domain.is_empty() {
            for domain in &ctx.output.domains {
                let resolver = StringResolver(domain.element.as_str());

                for rule in &self.core.spam.rules.domain {
                    if let Some(tag) = self
                        .eval_if::<CompactString, _>(
                            rule,
                            &SpamFilterResolver::new(ctx, &resolver, domain.location),
                            ctx.input.span_id,
                        )
                        .await
                    {
                        ctx.result.tags.insert(tag);
                    }
                }
            }
        }

        if !self.core.spam.rules.email.is_empty() {
            for email in &ctx.output.emails {
                for rule in &self.core.spam.rules.email {
                    if let Some(tag) = self
                        .eval_if::<CompactString, _>(
                            rule,
                            &SpamFilterResolver::new(ctx, &email.element, email.location),
                            ctx.input.span_id,
                        )
                        .await
                    {
                        ctx.result.tags.insert(tag);
                    }
                }
            }

            for (rcpt, location) in [
                (&ctx.output.recipients_to, Location::HeaderTo),
                (&ctx.output.recipients_cc, Location::HeaderCc),
                (&ctx.output.recipients_bcc, Location::HeaderBcc),
            ] {
                for email in rcpt {
                    for rule in &self.core.spam.rules.email {
                        if let Some(tag) = self
                            .eval_if::<CompactString, _>(
                                rule,
                                &SpamFilterResolver::new(ctx, email, location),
                                ctx.input.span_id,
                            )
                            .await
                        {
                            ctx.result.tags.insert(tag);
                        }
                    }
                }
            }
        }

        if !self.core.spam.rules.ip.is_empty() {
            for ip in &ctx.output.ips {
                let ip_resolver = IpResolver::new(ip.element);

                for rule in &self.core.spam.rules.ip {
                    if let Some(tag) = self
                        .eval_if::<CompactString, _>(
                            rule,
                            &SpamFilterResolver::new(ctx, &ip_resolver, ip.location),
                            ctx.input.span_id,
                        )
                        .await
                    {
                        ctx.result.tags.insert(tag);
                    }
                }
            }
        }

        if !self.core.spam.rules.header.is_empty() {
            for header in ctx.input.message.headers() {
                let raw = String::from_utf8_lossy(
                    ctx.input
                        .message
                        .raw_message()
                        .get(header.offset_start as usize..header.offset_end as usize)
                        .unwrap_or_default(),
                );
                let header_resolver = EmailHeader {
                    header,
                    raw: raw.as_ref(),
                };

                for rule in &self.core.spam.rules.header {
                    if let Some(tag) = self
                        .eval_if::<CompactString, _>(
                            rule,
                            &SpamFilterResolver::new(ctx, &header_resolver, Location::BodyText),
                            ctx.input.span_id,
                        )
                        .await
                    {
                        ctx.result.tags.insert(tag);
                    }
                }
            }
        }

        if !self.core.spam.rules.body.is_empty() {
            for (idx, part) in ctx.output.text_parts.iter().enumerate() {
                let text = match part {
                    TextPart::Plain { text_body, .. } => *text_body,
                    TextPart::Html { text_body, .. } => text_body.as_str(),
                    TextPart::None => continue,
                };
                let idx = idx as u32;
                let location = if ctx.input.message.text_body.contains(&idx) {
                    Location::BodyText
                } else if ctx.input.message.html_body.contains(&idx) {
                    Location::BodyHtml
                } else {
                    Location::Attachment
                };
                let string_resolver = StringResolver(text);

                for rule in &self.core.spam.rules.body {
                    if let Some(tag) = self
                        .eval_if::<CompactString, _>(
                            rule,
                            &SpamFilterResolver::new(ctx, &string_resolver, location),
                            ctx.input.span_id,
                        )
                        .await
                    {
                        ctx.result.tags.insert(tag);
                    }
                }
            }
        }

        if !self.core.spam.rules.any.is_empty() {
            let dummy_resolver = StringResolver("");
            for rule in &self.core.spam.rules.any {
                if let Some(tag) = self
                    .eval_if::<CompactString, _>(
                        rule,
                        &SpamFilterResolver::new(ctx, &dummy_resolver, Location::BodyText),
                        ctx.input.span_id,
                    )
                    .await
                {
                    ctx.result.tags.insert(tag);
                }
            }
        }
    }
}
