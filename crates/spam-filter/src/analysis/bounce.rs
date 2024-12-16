/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use std::future::Future;

use common::Server;
use mail_parser::MimeHeaders;

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeBounce: Sync + Send {
    fn spam_filter_analyze_bounce(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeBounce for Server {
    async fn spam_filter_analyze_bounce(&self, ctx: &mut SpamFilterContext<'_>) {
        let mut has_delivery_word = false;
        let mut has_undelivery_word = false;
        let mut has_failure_word = false;
        let mut has_report_word = false;
        let mut has_not_word = false;

        for word in ctx.output.subject.split_whitespace() {
            match word {
                "delivery" | "delivered" => {
                    has_delivery_word = true;
                }
                "undeliverable" | "undelivered" => {
                    has_undelivery_word = true;
                }
                "returned" | "failed" | "failure" | "warning" => {
                    has_failure_word = true;
                }

                "notice" | "report" | "status" | "mail" => {
                    has_report_word = true;
                }

                "couldn't" | "hasn't" | "not" => {
                    has_not_word = true;
                }
                _ => {}
            }
        }

        // Subject contains words or phrases typical for DSN
        let has_bounce_words = has_undelivery_word
            || (has_delivery_word && (has_failure_word || has_not_word))
            || (has_report_word && has_failure_word);

        if has_bounce_words {
            ctx.result.add_tag("SUBJ_BOUNCE_WORDS");
        }

        if !ctx.input.env_from.is_empty() {
            return;
        }

        match ctx.input.message.content_type() {
            Some(ct)
                if ct.ctype().eq_ignore_ascii_case("multipart")
                    && ct
                        .subtype()
                        .map_or(false, |s| s.eq_ignore_ascii_case("report"))
                    && ct.attribute("report-type").map_or(false, |a| {
                        a.eq_ignore_ascii_case("delivery-status")
                            || a.eq_ignore_ascii_case("disposition-notification")
                    }) =>
            {
                // Message is a DSN
                ctx.result.add_tag("BOUNCE");
            }
            _ => {
                let from_local = &ctx.output.from.email.local_part;

                if from_local.contains("mdaemon")
                    && ctx.input.message.header("X-MDDSN-Message").is_some()
                {
                    // Message is a DSN
                    ctx.result.add_tag("BOUNCE");
                } else if from_local.contains("postmaster") || from_local.contains("mailer-daemon")
                {
                    if has_bounce_words {
                        ctx.result.add_tag("BOUNCE");
                    } else {
                        for part in &ctx.input.message.parts {
                            if let Some(ct) = part.content_type() {
                                let st = ct.subtype().unwrap_or_default();
                                let ct = ct.ctype();

                                if (ct.eq_ignore_ascii_case("message")
                                    || ct.eq_ignore_ascii_case("text"))
                                    && (st.eq_ignore_ascii_case("rfc822-headers")
                                        || st.eq_ignore_ascii_case("rfc822"))
                                {
                                    // Message is a DSN
                                    ctx.result.add_tag("BOUNCE");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
