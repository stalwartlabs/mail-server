/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::Server;
use mail_parser::HeaderName;
use nlp::tokenizers::types::{TokenType, TypesTokenizer};
use smtp_proto::{MAIL_BODY_8BITMIME, MAIL_BODY_BINARYMIME, MAIL_SMTPUTF8};

use crate::{Email, SpamFilterContext};

pub trait SpamFilterAnalyzeFrom: Sync + Send {
    fn spam_filter_analyze_from(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeFrom for Server {
    async fn spam_filter_analyze_from(&self, ctx: &mut SpamFilterContext<'_>) {
        let mut from_count = 0;
        let mut from_raw = b"".as_slice();
        let mut crt = None;
        let mut dnt = None;

        for header in ctx.input.message.headers() {
            match &header.name {
                HeaderName::From => {
                    from_count += 1;
                    from_raw = ctx
                        .input
                        .message
                        .raw_message()
                        .get(header.offset_start as usize..header.offset_end as usize)
                        .unwrap_or_default();
                }
                HeaderName::Other(name) => {
                    if name.eq_ignore_ascii_case("X-Confirm-Reading-To") {
                        crt = ctx
                            .input
                            .header_as_address(header)
                            .map(|s| s.to_lowercase());
                    } else if name.eq_ignore_ascii_case("Disposition-Notification-To") {
                        dnt = ctx
                            .input
                            .header_as_address(header)
                            .map(|s| s.to_lowercase());
                    }
                }
                _ => {}
            }
        }

        match from_count {
            0 => {
                ctx.result.add_tag("MISSING_FROM");
            }
            1 => {}
            _ => {
                ctx.result.add_tag("MULTIPLE_FROM");
            }
        }

        let env_from_empty = ctx.output.env_from_addr.address.is_empty();
        let from_addr = &ctx.output.from.email;
        let from_name = ctx.output.from.name.as_deref().unwrap_or_default();
        if from_count > 0 {
            // Validate address
            let from_addr_is_valid = from_addr.is_valid();
            if !from_addr_is_valid {
                ctx.result.add_tag("FROM_INVALID");
            }

            // Validate from name
            let from_name_trimmed = from_name.trim();
            if from_name_trimmed.is_empty() {
                ctx.result.add_tag("FROM_NO_DN");
            } else if from_name_trimmed == from_addr.address {
                ctx.result.add_tag("FROM_DN_EQ_ADDR");
            } else {
                if from_addr_is_valid {
                    ctx.result.add_tag("FROM_HAS_DN");
                }

                if from_name_trimmed.contains('@') {
                    if let Some(from_name_addr) = TypesTokenizer::new(from_name_trimmed)
                        .tokenize_numbers(false)
                        .tokenize_urls(false)
                        .tokenize_urls_without_scheme(false)
                        .tokenize_emails(true)
                        .filter_map(|t| match t.word {
                            TokenType::Email(email) => {
                                let email = Email::new(email);
                                email.is_valid().then_some(email)
                            }
                            _ => None,
                        })
                        .next()
                    {
                        if (from_addr_is_valid
                            && from_name_addr.domain_part.sld != from_addr.domain_part.sld)
                            || (!env_from_empty
                                && ctx.output.env_from_addr.domain_part.sld
                                    != from_name_addr.domain_part.sld)
                            || (env_from_empty
                                && ctx.output.ehlo_host.sld != from_name_addr.domain_part.sld)
                        {
                            ctx.result.add_tag("SPOOF_DISPLAY_NAME");
                        } else {
                            ctx.result.add_tag("FROM_NEQ_DISPLAY_NAME");
                        }
                    }
                }
            }

            // Check sender
            if ctx.output.env_from_postmaster {
                ctx.result.add_tag("FROM_BOUNCE");
            }

            if !env_from_empty && ctx.output.env_from_addr.address == from_addr.address {
                ctx.result.add_tag("FROM_EQ_ENV_FROM");
            } else if from_addr_is_valid {
                if from_addr.domain_part.sld == ctx.output.ehlo_host.sld {
                    ctx.result.add_tag("FROMTLD_EQ_ENV_FROMTLD");
                } else if !ctx.output.env_from_postmaster {
                    ctx.result.add_tag("FORGED_SENDER");
                    ctx.result.add_tag("FROM_NEQ_ENV_FROM");
                }
            }

            // Validate FROM/TO relationship
            if ctx.output.recipients_to.len() + ctx.output.recipients_cc.len() == 1 {
                let rcpt = ctx
                    .output
                    .recipients_to
                    .first()
                    .or_else(|| ctx.output.recipients_cc.first())
                    .unwrap();
                if rcpt.email.address == from_addr.address {
                    ctx.result.add_tag("TO_EQ_FROM");
                } else if rcpt.email.domain_part.fqdn == from_addr.domain_part.fqdn {
                    ctx.result.add_tag("TO_DOM_EQ_FROM_DOM");
                }
            }

            // Validate encoding
            let from_raw_utf8 = std::str::from_utf8(from_raw);
            if !from_raw.is_ascii() {
                if (ctx.input.env_from_flags
                    & (MAIL_SMTPUTF8 | MAIL_BODY_8BITMIME | MAIL_BODY_BINARYMIME))
                    == 0
                {
                    ctx.result.add_tag("FROM_NEEDS_ENCODING");
                }

                if from_raw_utf8.is_err() {
                    ctx.result.add_tag("INVALID_FROM_8BIT");
                }
            }

            // Validate unnecessary encoding
            let from_raw_utf8 = from_raw_utf8.unwrap_or_default();
            if from_name.is_ascii()
                && from_addr.address.is_ascii()
                && from_raw_utf8.contains("=?")
                && from_raw_utf8.contains("?=")
            {
                if from_raw_utf8.contains("?q?") || from_raw_utf8.contains("?Q?") {
                    // From header is unnecessarily encoded in quoted-printable
                    ctx.result.add_tag("FROM_EXCESS_QP");
                } else if from_raw_utf8.contains("?b?") || from_raw_utf8.contains("?B?") {
                    // From header is unnecessarily encoded in base64
                    ctx.result.add_tag("FROM_EXCESS_BASE64");
                }
            }

            // Validate space in FROM
            if !from_name.is_empty()
                && !from_addr.address.is_empty()
                && !from_raw_utf8.contains(" <")
            {
                ctx.result.add_tag("NO_SPACE_IN_FROM");
            }

            // Check whether read confirmation address is different to from address
            if let Some(crt) = crt {
                if crt != from_addr.address {
                    ctx.result.add_tag("HEADER_RCONFIRM_MISMATCH");
                }
            }
        }

        if !env_from_empty {
            // Validate envelope address
            if ctx.output.env_from_addr.is_valid() {
                // Mail from no resolve to A or MX
                if matches!(
                    (
                        self.dns_exists_ip(&ctx.output.env_from_addr.domain_part.fqdn)
                            .await,
                        self.dns_exists_mx(&ctx.output.env_from_addr.domain_part.fqdn)
                            .await
                    ),
                    (Ok(false), Ok(false))
                ) {
                    // Helo no resolve to A or MX
                    ctx.result.add_tag("FROMHOST_NORES_A_OR_MX");
                }
            } else {
                ctx.result.add_tag("ENV_FROM_INVALID");
            }

            // Check whether disposition notification address is different to return path
            if let Some(dnt) = dnt {
                if dnt != ctx.output.env_from_addr.address {
                    ctx.result.add_tag("HEADER_FORGED_MDN");
                }
            }
        }
    }
}
