/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::{borrow::Cow, future::Future, time::Duration};

use common::Server;
use common::config::spamfilter::{Element, IpResolver, Location};
use common::scripts::IsMixedCharset;
use common::scripts::functions::unicode::CharUtils;
use hyper::{Uri, header::LOCATION};
use nlp::tokenizers::types::TokenType;
use reqwest::redirect::Policy;

use crate::modules::dnsbl::check_dnsbl;
use crate::modules::expression::StringResolver;
use crate::modules::html::SRC;
use crate::{
    Hostname, SpamFilterContext, TextPart,
    modules::html::{A, HREF, HtmlToken},
};

use super::{ElementLocation, is_trusted_domain, is_url_redirector};

pub trait SpamFilterAnalyzeUrl: Sync + Send {
    fn spam_filter_analyze_url(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

#[derive(Clone, Debug)]
pub struct UrlParts<'x> {
    pub url: String,
    pub url_original: Cow<'x, str>,
    pub url_parsed: Option<UrlParsed>,
}

#[derive(Clone, Debug)]
pub struct UrlParsed {
    pub parts: Uri,
    pub host: Hostname,
}

impl SpamFilterAnalyzeUrl for Server {
    async fn spam_filter_analyze_url(&self, ctx: &mut SpamFilterContext<'_>) {
        // Extract URLs
        let mut urls: HashSet<ElementLocation<UrlParts<'static>>> =
            HashSet::from_iter(ctx.output.subject_tokens.iter().filter_map(|t| match t {
                TokenType::Url(url) | TokenType::UrlNoScheme(url) => Some(ElementLocation::new(
                    url.to_owned(),
                    Location::HeaderSubject,
                )),
                _ => None,
            }));
        for (part_id, part) in ctx.output.text_parts.iter().enumerate() {
            let part_id = part_id as u32;
            let is_body = ctx.input.message.text_body.contains(&part_id)
                || ctx.input.message.html_body.contains(&part_id);

            let tokens = match part {
                TextPart::Plain { tokens, .. } => tokens,
                TextPart::Html {
                    html_tokens,
                    tokens,
                    ..
                } => {
                    for token in html_tokens {
                        if let HtmlToken::StartTag { attributes, .. } = token {
                            for (attr, value) in attributes {
                                match value {
                                    Some(value) if [HREF, SRC].contains(attr) => {
                                        urls.insert(ElementLocation::new(
                                            UrlParts::new(value.trim().to_string()),
                                            if is_body {
                                                Location::BodyHtml
                                            } else {
                                                Location::Attachment
                                            },
                                        ));
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    tokens
                }
                TextPart::None => &[][..],
            };

            for token in tokens {
                match token {
                    TokenType::Url(url) | TokenType::UrlNoScheme(url) => {
                        if is_body && !ctx.result.has_tag("RCPT_DOMAIN_IN_BODY") {
                            if let Some(url_parsed) = &url.url_parsed {
                                let host = url_parsed.host.sld_or_default();
                                for rcpt in ctx.output.all_recipients() {
                                    if rcpt.email.domain_part.sld_or_default() == host {
                                        ctx.result.add_tag("RCPT_DOMAIN_IN_BODY");
                                        break;
                                    }
                                }
                            }
                        }

                        urls.insert(ElementLocation::new(
                            url.to_owned(),
                            if is_body {
                                Location::BodyHtml
                            } else {
                                Location::Attachment
                            },
                        ));
                    }
                    _ => {}
                }
            }

            if is_body {
                let is_single = match part {
                    TextPart::Plain { tokens, .. } => is_single_url(tokens),
                    TextPart::Html {
                        html_tokens,
                        tokens,
                        ..
                    } => is_single_html_url(html_tokens, tokens),
                    TextPart::None => false,
                };

                if is_single {
                    ctx.result.add_tag("URL_ONLY");
                }
            }
        }

        let mut redirected_urls = HashSet::new();
        for url in &urls {
            for ch in url.element.url.chars() {
                if ch.is_zwsp() {
                    ctx.result.add_tag("ZERO_WIDTH_SPACE_URL");
                }

                if ch.is_obscured() {
                    ctx.result.add_tag("SUSPICIOUS_URL");
                }
            }

            // Skip non-URLs such as 'data:' and 'mailto:'
            if !url.element.url.contains("://") {
                continue;
            }

            // Obtain parse url
            let url_parsed = if let Some(url_parsed) = &url.element.url_parsed {
                url_parsed
            } else {
                // URL could not be parsed
                ctx.result.add_tag("UNPARSABLE_URL");
                continue;
            };
            let host_sld = url_parsed.host.sld_or_default();

            // Skip local and trusted domains
            if is_trusted_domain(self, host_sld, ctx.input.span_id).await {
                continue;
            }

            if let Some(ip) = url_parsed.host.ip {
                // Check IP DNSBL
                check_dnsbl(self, ctx, &IpResolver::new(ip), Element::Ip, url.location).await;
            } else if is_url_redirector(self, host_sld, ctx.input.span_id).await {
                // Check for redirectors
                ctx.result.add_tag("REDIRECTOR_URL");

                if !ctx.result.has_tag("URL_REDIRECTOR_NESTED") {
                    let mut redirect_count = 1;
                    let mut url_redirect = Cow::Borrowed(url.element.url.as_str());

                    while redirect_count <= 3 {
                        match http_get_header(
                            url_redirect.as_ref(),
                            LOCATION,
                            Duration::from_secs(5),
                        )
                        .await
                        {
                            Ok(Some(location)) => {
                                let location = UrlParts::new(location);
                                if let Some(location_parsed) = &location.url_parsed {
                                    if is_url_redirector(
                                        self,
                                        location_parsed.host.sld_or_default(),
                                        ctx.input.span_id,
                                    )
                                    .await
                                    {
                                        url_redirect = Cow::Owned(location.url);
                                        redirect_count += 1;
                                        continue;
                                    } else {
                                        redirected_urls
                                            .insert(ElementLocation::new(location, url.location));
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(err) => {
                                trc::error!(err.span_id(ctx.input.span_id));
                            }
                        }
                        break;
                    }

                    if redirect_count > 3 {
                        ctx.result.add_tag("URL_REDIRECTOR_NESTED");
                    }
                }
            }
        }

        urls.extend(redirected_urls);

        for (el, url_parsed) in urls.iter().filter_map(|el| {
            el.element
                .url_parsed
                .as_ref()
                .map(|url_parsed| (el, url_parsed))
        }) {
            let host = &url_parsed.host;

            if host.ip.is_none() {
                if !host.fqdn.is_ascii() {
                    if let Ok(cured_host) = decancer::cure(&host.fqdn, decancer::Options::default())
                    {
                        let cured_host = cured_host.to_string();
                        if cured_host != host.fqdn
                            && matches!(self.dns_exists_ip(&cured_host).await, Ok(true))
                        {
                            ctx.result.add_tag("HOMOGRAPH_URL");
                        }
                    }

                    if host.fqdn.is_mixed_charset() {
                        ctx.result.add_tag("MIXED_CHARSET_URL");
                    }
                }

                // Check Domain DNSBL
                if let Some(sld) = &host.sld {
                    check_dnsbl(
                        self,
                        ctx,
                        &StringResolver(sld),
                        Element::Domain,
                        el.location,
                    )
                    .await;
                }
            } else {
                // URL is an ip address
                ctx.result.add_tag("SUSPICIOUS_URL");
            }

            // Check URL DNSBL
            check_dnsbl(self, ctx, &el.element, Element::Url, el.location).await;
        }

        // Update context
        ctx.output.urls = urls;
    }
}

#[allow(unreachable_code)]
#[allow(unused_variables)]
async fn http_get_header(
    url: &str,
    header: hyper::header::HeaderName,
    timeout: Duration,
) -> trc::Result<Option<String>> {
    #[cfg(feature = "test_mode")]
    {
        return if url.contains("redirect.") {
            Ok(url.split_once("/?").unwrap().1.to_string().into())
        } else {
            Ok(None)
        };
    }
    reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/118.0")
        .timeout(timeout)
        .redirect(Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|err| {
            trc::SieveEvent::RuntimeError
                .into_err()
                .reason(err)
                .details("Failed to build request")
        })?
        .get(url)
        .send()
        .await
        .map_err(|err| {
            trc::SieveEvent::RuntimeError
                .into_err()
                .reason(err)
                .details("Failed to send request")
        })
        .map(|response| {
            response
                .headers()
                .get(header)
                .and_then(|h| h.to_str().ok())
                .map(|h| h.to_string())
        })
}

fn is_single_url<T, E, U, I>(tokens: &[TokenType<T, E, U, I>]) -> bool {
    let mut url_count = 0;
    let mut word_count = 0;

    for token in tokens {
        match token {
            TokenType::Alphabetic(_)
            | TokenType::Alphanumeric(_)
            | TokenType::Integer(_)
            | TokenType::Email(_)
            | TokenType::Float(_) => {
                word_count += 1;
            }
            TokenType::Url(_) | TokenType::UrlNoScheme(_) => {
                url_count += 1;
            }
            _ => {}
        }
    }

    url_count == 1 && word_count <= 1
}

fn is_single_html_url<T, E, U, I>(
    html_tokens: &[HtmlToken],
    tokens: &[TokenType<T, E, U, I>],
) -> bool {
    let mut url_count = 0;
    let mut word_count = 0;

    for token in tokens {
        match token {
            TokenType::Alphabetic(_)
            | TokenType::Alphanumeric(_)
            | TokenType::Integer(_)
            | TokenType::Email(_)
            | TokenType::Float(_) => {
                word_count += 1;
            }
            TokenType::Url(_) | TokenType::UrlNoScheme(_) => {
                url_count += 1;
            }
            _ => {}
        }
    }

    if word_count > 1 || url_count != 1 {
        return false;
    }

    url_count = 0;

    for token in html_tokens {
        if matches!(token, HtmlToken::StartTag { name, attributes, .. } if *name == A && attributes.iter().any(|(k, _)| *k == HREF))
        {
            url_count += 1;
        }
    }

    url_count == 1
}

impl PartialEq for UrlParts<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Eq for UrlParts<'_> {}

impl Hash for UrlParts<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

impl<'x> UrlParts<'x> {
    pub fn new(url: impl Into<Cow<'x, str>>) -> Self {
        let url_original = url.into();
        let url = url_original.trim().to_lowercase();

        Self {
            url_parsed: url.parse::<Uri>().ok().and_then(|url_parsed| {
                if url_parsed.host().is_some() {
                    Some(UrlParsed {
                        host: Hostname::new(url_parsed.host().unwrap()),
                        parts: url_parsed,
                    })
                } else {
                    None
                }
            }),
            url,
            url_original,
        }
    }

    pub fn to_owned(&self) -> UrlParts<'static> {
        UrlParts {
            url: self.url.clone(),
            url_original: Cow::Owned(self.url_original.clone().into_owned()),
            url_parsed: self.url_parsed.clone(),
        }
    }
}
