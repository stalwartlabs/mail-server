/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::Server;
use mail_parser::HeaderName;

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeReplyTo: Sync + Send {
    fn spam_filter_analyze_reply_to(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeReplyTo for Server {
    async fn spam_filter_analyze_reply_to(&self, ctx: &mut SpamFilterContext<'_>) {
        let mut reply_to_raw = b"".as_slice();
        let mut is_from_list = false;

        for header in ctx.input.message.headers() {
            match &header.name {
                HeaderName::ReplyTo => {
                    reply_to_raw = ctx
                        .input
                        .message
                        .raw_message()
                        .get(header.offset_start as usize..header.offset_end as usize)
                        .unwrap_or_default();
                }
                HeaderName::ListUnsubscribe | HeaderName::ListId => {
                    is_from_list = true;
                }

                HeaderName::Other(name) => {
                    if !is_from_list {
                        is_from_list = name.eq_ignore_ascii_case("X-To-Get-Off-This-List")
                            || name.eq_ignore_ascii_case("X-List")
                            || name.eq_ignore_ascii_case("Auto-Submitted");
                    }
                }
                _ => {}
            }
        }

        if reply_to_raw.is_empty() {
            return;
        }

        if let Some(reply_to) = &ctx.output.reply_to {
            let reply_to_name = reply_to.name.as_deref().unwrap_or_default();
            ctx.result.add_tag("HAS_REPLYTO");

            if reply_to.email == ctx.output.from.email {
                ctx.result.add_tag("REPLYTO_EQ_FROM");
            } else {
                if reply_to.email.domain_part.sld == ctx.output.from.email.domain_part.sld {
                    ctx.result.add_tag("REPLYTO_DOM_EQ_FROM_DOM");
                } else {
                    if !is_from_list
                        && ctx
                            .output
                            .all_recipients()
                            .any(|r| r.email == reply_to.email)
                    {
                        ctx.result.add_tag("REPLYTO_EQ_TO_ADDR");
                    } else {
                        ctx.result.add_tag("REPLYTO_DOM_NEQ_FROM_DOM");
                    }

                    if !(is_from_list
                        || ctx
                            .output
                            .recipients_to
                            .iter()
                            .any(|r| r.email == ctx.output.from.email)
                        || ctx
                            .output
                            .env_to_addr
                            .iter()
                            .any(|r| r.domain_part.sld == ctx.output.from.email.domain_part.sld)
                        || ctx.output.env_to_addr.len() == 1
                            && ctx.output.env_to_addr.contains(&ctx.output.from.email))
                    {
                        ctx.result.add_tag("SPOOF_REPLYTO");
                    }
                }

                if !reply_to_name.is_empty()
                    && reply_to_name == ctx.output.from.name.as_deref().unwrap_or_default()
                {
                    ctx.result.add_tag("REPLYTO_DN_EQ_FROM_DN");
                }
            }

            if reply_to.email == ctx.output.env_from_addr {
                ctx.result.add_tag("REPLYTO_ADDR_EQ_FROM");
            }

            // Validate unnecessary encoding
            let reply_to_raw_utf8 = std::str::from_utf8(reply_to_raw).unwrap_or_default();
            if reply_to.email.address.is_ascii()
                && reply_to_name.is_ascii()
                && reply_to_raw_utf8.contains("=?")
                && reply_to_raw_utf8.contains("?=")
            {
                if reply_to_raw_utf8.contains("?q?") || reply_to_raw_utf8.contains("?Q?") {
                    // Reply-To header is unnecessarily encoded in quoted-printable
                    ctx.result.add_tag("REPLYTO_EXCESS_QP");
                } else if reply_to_raw_utf8.contains("?b?") || reply_to_raw_utf8.contains("?B?") {
                    // Reply-To header is unnecessarily encoded in base64
                    ctx.result.add_tag("REPLYTO_EXCESS_BASE64");
                }
            }
        } else {
            ctx.result.add_tag("REPLYTO_UNPARSABLE");
        }
    }
}
