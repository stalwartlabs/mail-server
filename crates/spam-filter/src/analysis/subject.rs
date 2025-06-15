/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::Server;
use mail_parser::HeaderName;
use nlp::tokenizers::types::TokenType;
use smtp_proto::{MAIL_BODY_8BITMIME, MAIL_BODY_BINARYMIME, MAIL_SMTPUTF8};

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeSubject: Sync + Send {
    fn spam_filter_analyze_subject(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeSubject for Server {
    async fn spam_filter_analyze_subject(&self, ctx: &mut SpamFilterContext<'_>) {
        let mut subject_raw = b"".as_slice();

        for header in ctx.input.message.headers() {
            if header.name == HeaderName::Subject {
                subject_raw = ctx
                    .input
                    .message
                    .raw_message()
                    .get(header.offset_start as usize..header.offset_end as usize)
                    .unwrap_or_default();
                break;
            }
        }

        if subject_raw.is_empty() {
            // Missing subject header
            ctx.result.add_tag("MISSING_SUBJECT");
            return;
        }

        let mut word_count = 0;
        let mut upper_count = 0;
        let mut lower_count = 0;

        let mut last_ch = ' ';
        let mut is_ascii = true;

        for ch in ctx.output.subject_thread.chars() {
            if !ch.is_whitespace() {
                if last_ch.is_whitespace() {
                    word_count += 1;
                }

                match ch {
                    '$' | '€' | '£' | '¥' | '₹' | '₽' | '₿' => {
                        ctx.result.add_tag("SUBJECT_HAS_CURRENCY");
                    }
                    _ => {
                        if ch.is_alphabetic() {
                            if ch.is_uppercase() {
                                upper_count += 1;
                            } else {
                                lower_count += 1;
                            }
                        }
                    }
                }
            }

            if !ch.is_ascii() {
                is_ascii = false;
            }

            last_ch = ch;
        }

        if ctx.output.subject_lc.is_empty() {
            // Subject is empty
            ctx.result.add_tag("EMPTY_SUBJECT");
        } else if ctx.output.subject.ends_with(' ') {
            // Subject ends with whitespace
            ctx.result.add_tag("SUBJECT_ENDS_SPACES");
        }

        if ctx.output.subject_thread.len() >= 10
            && word_count > 1
            && upper_count > 2
            && lower_count == 0
        {
            // Subject contains mostly capital letters
            ctx.result.add_tag("SUBJ_ALL_CAPS");
        }

        for token in &ctx.output.subject_tokens {
            match token {
                TokenType::Url(url) => {
                    // Subject contains URL
                    ctx.result.add_tag("URL_IN_SUBJECT");

                    if let Some(url_parsed) = &url.url_parsed {
                        let host = url_parsed.host.sld_or_default();
                        for rcpt in ctx.output.all_recipients() {
                            if rcpt.email.domain_part.sld_or_default() == host {
                                ctx.result.add_tag("RCPT_DOMAIN_IN_SUBJECT");
                                break;
                            }
                        }
                    }
                }
                TokenType::UrlNoScheme(url) => {
                    if let Some(url_parsed) = &url.url_parsed {
                        let host = url_parsed.host.sld_or_default();
                        for rcpt in ctx.output.all_recipients() {
                            if rcpt.email.domain_part.sld_or_default() == host {
                                ctx.result.add_tag("RCPT_DOMAIN_IN_SUBJECT");
                                break;
                            }
                        }
                    }
                }
                TokenType::Email(email) => {
                    // Subject contains recipient
                    if ctx.output.env_to_addr.contains(email)
                        || ctx
                            .output
                            .all_recipients()
                            .any(|r| r.email.address == email.address)
                    {
                        ctx.result.add_tag("RCPT_IN_SUBJECT");
                    } else {
                        let host = email.domain_part.sld_or_default();
                        for rcpt in ctx.output.all_recipients() {
                            if rcpt.email.address == email.address {
                                ctx.result.add_tag("RCPT_IN_SUBJECT");
                                break;
                            } else if rcpt.email.domain_part.sld_or_default() == host {
                                ctx.result.add_tag("RCPT_DOMAIN_IN_SUBJECT");
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Validate encoding
        let subject_raw_utf8 = std::str::from_utf8(subject_raw);
        if !subject_raw.is_ascii() {
            if (ctx.input.env_from_flags
                & (MAIL_SMTPUTF8 | MAIL_BODY_8BITMIME | MAIL_BODY_BINARYMIME))
                == 0
            {
                ctx.result.add_tag("SUBJECT_NEEDS_ENCODING");
            }

            if subject_raw_utf8.is_err() {
                ctx.result.add_tag("INVALID_SUBJECT_8BIT");
            }
        }

        // Validate unnecessary encoding
        let subject_raw_utf8 = subject_raw_utf8.unwrap_or_default();
        if is_ascii && subject_raw_utf8.contains("=?") && subject_raw_utf8.contains("?=") {
            if subject_raw_utf8.contains("?q?") || subject_raw_utf8.contains("?Q?") {
                // Subject header is unnecessarily encoded in quoted-printable
                ctx.result.add_tag("SUBJ_EXCESS_QP");
            } else if subject_raw_utf8.contains("?b?") || subject_raw_utf8.contains("?B?") {
                // Subject header is unnecessarily encoded in base64
                ctx.result.add_tag("SUBJ_EXCESS_BASE64");
            }
        }
    }
}
