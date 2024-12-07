use std::future::Future;

use common::Core;
use mail_parser::HeaderName;
use smtp_proto::{MAIL_BODY_8BITMIME, MAIL_BODY_BINARYMIME, MAIL_SMTPUTF8};

use crate::{Email, SpamFilterContext};

pub trait SpamFilterAnalyzeFrom: Sync + Send {
    fn spam_filter_analyze_from(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

const SERVICE_ACCOUNTS: [&str; 9] = [
    "www-data",
    "anonymous",
    "ftp",
    "apache",
    "nobody",
    "guest",
    "nginx",
    "web",
    "www",
];
pub(crate) const TITLES: [&str; 7] = ["mr. ", "mrs. ", "ms. ", "dr. ", "prof. ", "rev. ", "hon. "];

impl SpamFilterAnalyzeFrom for Core {
    async fn spam_filter_analyze_from(&self, ctx: &mut SpamFilterContext<'_>) {
        let mut from_count = 0;
        let mut from_raw = b"".as_slice();
        let mut crt = None;
        let mut dnt = None;
        let mut sender = None;

        for header in ctx.input.message.headers() {
            match &header.name {
                HeaderName::From => {
                    from_count += 1;
                    from_raw = ctx
                        .input
                        .message
                        .raw_message()
                        .get(header.offset_start..header.offset_end)
                        .unwrap_or_default();
                }
                HeaderName::Sender => {
                    sender = header
                        .value()
                        .as_address()
                        .and_then(|addrs| addrs.first())
                        .and_then(|addr| addr.address())
                        .map(Email::new);
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
        let mut is_from_service_account = false;
        let mut is_www_dot_domain = false;
        let from_addr = &ctx.output.from.email;
        let from_name = ctx.output.from.name.as_deref().unwrap_or_default();
        if from_count > 0 {
            // Validate address
            let from_addr_is_valid = from_addr.is_valid();
            if from_addr_is_valid {
                if SERVICE_ACCOUNTS.contains(&from_addr.local_part.as_str()) {
                    is_from_service_account = true;
                }
                if from_addr.domain_part.fqdn.starts_with("www.") {
                    is_www_dot_domain = true;
                }
                if self
                    .spam
                    .list_freemail_providers
                    .contains(from_addr.domain_part.sld.as_deref().unwrap_or_default())
                {
                    ctx.result.add_tag("FREEMAIL_FROM");
                } else if self
                    .spam
                    .list_disposable_providers
                    .contains(from_addr.domain_part.sld.as_deref().unwrap_or_default())
                {
                    ctx.result.add_tag("DISPOSABLE_FROM");
                }
            } else {
                ctx.result.add_tag("FROM_INVALID");
            }

            // Validate from name
            let from_name_trimmed = from_name.trim();
            if from_name_trimmed.is_empty() {
                ctx.result.add_tag("FROM_NO_DN");
            } else if from_name_trimmed == from_addr.address {
                ctx.result.add_tag("FROM_DN_EQ_ADDR");
            } else {
                let from_name_addr = Email::new(from_name_trimmed);
                if from_addr_is_valid {
                    ctx.result.add_tag("FROM_HAS_DN");
                }
                if from_name_addr.is_valid() {
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
                } else {
                    for title in TITLES {
                        if from_name.contains(title) {
                            ctx.result.add_tag("FROM_NAME_HAS_TITLE");
                            break;
                        }
                    }

                    if from_name.contains("  ") {
                        ctx.result.add_tag("FROM_NAME_EXCESS_SPACE");
                    }
                }
            }

            // Check sender
            if ctx.output.env_from_postmaster {
                ctx.result.add_tag("FROM_BOUNCE");
            }

            if (!env_from_empty && ctx.output.env_from_addr.address == from_addr.address)
                || (!ctx.output.env_from_postmaster
                    && from_addr_is_valid
                    && from_addr.domain_part.sld == ctx.output.ehlo_host.sld)
            {
                ctx.result.add_tag("FROM_EQ_ENVFROM");
            } else if from_addr_is_valid {
                ctx.result.add_tag("FORGED_SENDER");
                ctx.result.add_tag("FROM_NEQ_ENVFROM");
            }

            if from_addr.local_part.contains("+") {
                ctx.result.add_tag("TAGGED_FROM");
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
                ctx.result.add_tag("R_NO_SPACE_IN_FROM");
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
                if SERVICE_ACCOUNTS.contains(&ctx.output.env_from_addr.local_part.as_str()) {
                    ctx.result.add_tag("ENVFROM_SERVICE_ACCT");
                }
                if self.spam.list_freemail_providers.contains(
                    ctx.output
                        .env_from_addr
                        .domain_part
                        .sld
                        .as_deref()
                        .unwrap_or_default(),
                ) {
                    ctx.result.add_tag("FREEMAIL_ENVFROM");
                } else if self.spam.list_disposable_providers.contains(
                    ctx.output
                        .env_from_addr
                        .domain_part
                        .sld
                        .as_deref()
                        .unwrap_or_default(),
                ) {
                    ctx.result.add_tag("DISPOSABLE_ENVFROM");
                }

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
                ctx.result.add_tag("ENVFROM_INVALID");
            }

            // Check whether disposition notification address is different to return path
            if let Some(dnt) = dnt {
                if dnt != ctx.output.env_from_addr.address {
                    ctx.result.add_tag("HEADER_FORGED_MDN");
                }
            }
        }

        for addr in [
            ctx.output.reply_to.as_ref().map(|s| &s.email),
            sender.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if !is_from_service_account && SERVICE_ACCOUNTS.contains(&addr.local_part.as_str()) {
                is_from_service_account = true;
            }

            if !is_www_dot_domain && addr.domain_part.fqdn.starts_with("www.") {
                is_www_dot_domain = true;
            }
        }

        if is_from_service_account {
            ctx.result.add_tag("FROM_SERVICE_ACCT");
        }

        if is_www_dot_domain {
            ctx.result.add_tag("WWW_DOT_DOMAIN");
        }
    }
}
