/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::Server;
use mail_parser::HeaderName;
use store::ahash::AHashSet;

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeHeaders: Sync + Send {
    fn spam_filter_analyze_headers(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeHeaders for Server {
    async fn spam_filter_analyze_headers(&self, ctx: &mut SpamFilterContext<'_>) {
        let mut list_score = 0.0;
        let mut unique_headers = AHashSet::new();
        let raw_message = ctx.input.message.raw_message();

        for header in ctx.input.message.headers() {
            // Add header exists tag
            let hdr_name = header.name();
            let mut tag: String = String::with_capacity(hdr_name.len() + 5);
            tag.push_str("X_HDR_");
            for ch in hdr_name.chars() {
                if ch.is_ascii_alphanumeric() {
                    tag.push(ch.to_ascii_uppercase());
                } else if ch == '-' {
                    tag.push('_');
                } else {
                    tag.push(' ');
                }
            }
            ctx.result.add_tag(tag);

            match &header.name {
                HeaderName::ContentType
                | HeaderName::ContentTransferEncoding
                | HeaderName::Date
                | HeaderName::From
                | HeaderName::Sender
                | HeaderName::To
                | HeaderName::Cc
                | HeaderName::Bcc
                | HeaderName::ReplyTo
                | HeaderName::Subject
                | HeaderName::MessageId
                | HeaderName::References
                | HeaderName::InReplyTo => {
                    if !unique_headers.insert(header.name.clone()) {
                        ctx.result.add_tag("MULTIPLE_UNIQUE_HEADERS");
                    }

                    if !matches!(raw_message.get(header.offset_start as usize), Some(b' ')) {
                        ctx.result.add_tag("HEADER_EMPTY_DELIMITER");
                    }
                }
                HeaderName::ListArchive
                | HeaderName::ListOwner
                | HeaderName::ListHelp
                | HeaderName::ListPost => {
                    list_score += 0.125;
                }
                HeaderName::ListId => {
                    list_score += 0.5125;
                }
                HeaderName::ListSubscribe => {
                    list_score += 0.25;
                }
                HeaderName::ListUnsubscribe => {
                    list_score += 0.25;
                    ctx.result.add_tag("HAS_LIST_UNSUB");
                }
                HeaderName::Other(name) => {
                    let value = header
                        .value()
                        .as_text()
                        .unwrap_or_default()
                        .trim()
                        .to_lowercase();

                    if name.eq_ignore_ascii_case("Precedence") {
                        if value == "bulk" {
                            list_score += 0.25;
                            ctx.result.add_tag("PRECEDENCE_BULK");
                        } else if value == "list" {
                            list_score += 0.25;
                        }
                    } else if name.eq_ignore_ascii_case("X-Loop") {
                        list_score += 0.125;
                    } else if name.eq_ignore_ascii_case("X-Priority") {
                        match value.parse::<i32>().unwrap_or(i32::MAX) {
                            0 => {
                                ctx.result.add_tag("HAS_X_PRIO_ZERO");
                            }
                            1 => {
                                ctx.result.add_tag("HAS_X_PRIO_ONE");
                            }
                            2 => {
                                ctx.result.add_tag("HAS_X_PRIO_TWO");
                            }
                            3 | 4 => {
                                ctx.result.add_tag("HAS_X_PRIO_THREE");
                            }
                            4..=10000 => {
                                ctx.result.add_tag("HAS_X_PRIO_FIVE");
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        if list_score >= 1.0 {
            ctx.result.add_tag("MAILLIST");
        }

        if unique_headers.is_empty() {
            ctx.result.add_tag("MISSING_ESSENTIAL_HEADERS");
        }
    }
}
