/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::{
    config::spamfilter::{Element, Location},
    Server,
};

use crate::{
    modules::expression::{EmailHeader, IpResolver, SpamFilterResolver, StringResolver},
    SpamFilterContext, TextPart,
};

pub trait SpamFilterAnalyzeRules: Sync + Send {
    fn spam_filter_analyze_rules(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeRules for Server {
    async fn spam_filter_analyze_rules(&self, ctx: &mut SpamFilterContext<'_>) {
        for rule in &self.core.spam.rules {
            match rule.scope {
                Element::Url => {
                    for url in &ctx.output.urls {
                        if let Some(tag) = self
                            .eval_if::<String, _>(
                                &rule.rule,
                                &SpamFilterResolver::new(ctx, &url.element, url.location),
                                ctx.input.span_id,
                            )
                            .await
                        {
                            ctx.result.tags.insert(tag);
                        }
                    }
                }
                Element::Domain => {
                    for domain in &ctx.output.domains {
                        if let Some(tag) = self
                            .eval_if::<String, _>(
                                &rule.rule,
                                &SpamFilterResolver::new(
                                    ctx,
                                    &StringResolver(domain.element.as_str()),
                                    domain.location,
                                ),
                                ctx.input.span_id,
                            )
                            .await
                        {
                            ctx.result.tags.insert(tag);
                        }
                    }
                }
                Element::Email => {
                    for email in &ctx.output.emails {
                        if let Some(tag) = self
                            .eval_if::<String, _>(
                                &rule.rule,
                                &SpamFilterResolver::new(ctx, &email.element, email.location),
                                ctx.input.span_id,
                            )
                            .await
                        {
                            ctx.result.tags.insert(tag);
                        }
                    }

                    for (rcpt, location) in [
                        (&ctx.output.recipients_to, Location::HeaderTo),
                        (&ctx.output.recipients_cc, Location::HeaderCc),
                        (&ctx.output.recipients_bcc, Location::HeaderBcc),
                    ] {
                        for email in rcpt {
                            if let Some(tag) = self
                                .eval_if::<String, _>(
                                    &rule.rule,
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
                Element::Ip => {
                    for ip in &ctx.output.ips {
                        if let Some(tag) = self
                            .eval_if::<String, _>(
                                &rule.rule,
                                &SpamFilterResolver::new(ctx, &IpResolver(ip.element), ip.location),
                                ctx.input.span_id,
                            )
                            .await
                        {
                            ctx.result.tags.insert(tag);
                        }
                    }
                }
                Element::Header => {
                    for header in ctx.input.message.headers() {
                        let raw = String::from_utf8_lossy(
                            ctx.input
                                .message
                                .raw_message()
                                .get(header.offset_start..header.offset_end)
                                .unwrap_or_default(),
                        );

                        if let Some(tag) = self
                            .eval_if::<String, _>(
                                &rule.rule,
                                &SpamFilterResolver::new(
                                    ctx,
                                    &EmailHeader {
                                        header,
                                        raw: raw.as_ref(),
                                    },
                                    Location::BodyText,
                                ),
                                ctx.input.span_id,
                            )
                            .await
                        {
                            ctx.result.tags.insert(tag);
                        }
                    }
                }
                Element::Body => {
                    for (idx, part) in ctx.output.text_parts.iter().enumerate() {
                        let text = match part {
                            TextPart::Plain { text_body, .. } => *text_body,
                            TextPart::Html { text_body, .. } => text_body.as_str(),
                            TextPart::None => continue,
                        };
                        let location = if ctx.input.message.text_body.contains(&idx) {
                            Location::BodyText
                        } else if ctx.input.message.html_body.contains(&idx) {
                            Location::BodyHtml
                        } else {
                            Location::Attachment
                        };

                        if let Some(tag) = self
                            .eval_if::<String, _>(
                                &rule.rule,
                                &SpamFilterResolver::new(ctx, &StringResolver(text), location),
                                ctx.input.span_id,
                            )
                            .await
                        {
                            ctx.result.tags.insert(tag);
                        }
                    }
                }
                Element::Any => {
                    if let Some(tag) = self
                        .eval_if::<String, _>(
                            &rule.rule,
                            &SpamFilterResolver::new(ctx, &StringResolver(""), Location::BodyText),
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
}
