/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::{borrow::Cow, future::Future, time::Duration};

use common::config::spamfilter::{Element, Location};
use common::scripts::functions::unicode::CharUtils;
use common::Server;
use hyper::{header::LOCATION, Uri};
use nlp::tokenizers::types::TokenType;
use reqwest::redirect::Policy;
use unicode_security::MixedScript;

use crate::modules::dnsbl::is_dnsbl;
use crate::modules::expression::{IpResolver, SpamFilterResolver, StringResolver};
use crate::modules::html::SRC;
use crate::{
    modules::html::{HtmlToken, A, HREF},
    Hostname, SpamFilterContext, TextPart,
};

use super::{is_trusted_domain, is_url_redirector, ElementLocation};

pub trait SpamFilterAnalyzeUrl: Sync + Send {
    fn spam_filter_analyze_url(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

pub struct UrlParts {
    pub url: String,
    pub url_parsed: Option<UrlParsed>,
}

pub struct UrlParsed {
    pub parts: Uri,
    pub host: Hostname,
}

impl SpamFilterAnalyzeUrl for Server {
    async fn spam_filter_analyze_url(&self, ctx: &mut SpamFilterContext<'_>) {
        // Extract URLs
        let mut urls: HashSet<ElementLocation<String>> = HashSet::from_iter(
            ctx.output
                .subject_tokens
                .iter()
                .filter_map(|t| t.url_lowercase(false))
                .map(|url| ElementLocation::new(url, Location::HeaderSubject)),
        );
        for (part_id, part) in ctx.output.text_parts.iter().enumerate() {
            let is_body = ctx.input.message.text_body.contains(&part_id)
                || ctx.input.message.html_body.contains(&part_id);

            match part {
                TextPart::Plain { tokens, .. } => {
                    urls.extend(
                        tokens
                            .iter()
                            .filter_map(|t| t.url_lowercase(false))
                            .map(|url| {
                                ElementLocation::new(
                                    url,
                                    if is_body {
                                        Location::BodyText
                                    } else {
                                        Location::Attachment
                                    },
                                )
                            }),
                    );
                }
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
                                            value.trim().to_lowercase(),
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
                    urls.extend(
                        tokens
                            .iter()
                            .filter_map(|t| t.url_lowercase(false))
                            .map(|url| {
                                ElementLocation::new(
                                    url,
                                    if is_body {
                                        Location::BodyHtml
                                    } else {
                                        Location::Attachment
                                    },
                                )
                            }),
                    );
                }
                TextPart::None => {}
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

        for url in urls {
            for ch in url.element.chars() {
                if ch.is_zwsp() {
                    ctx.result.add_tag("ZERO_WIDTH_SPACE_URL");
                }

                if ch.is_obscured() {
                    ctx.result.add_tag("R_SUSPICIOUS_URL");
                }
            }

            // Skip non-URLs such as 'data:' and 'mailto:'
            if !url.element.contains("://") {
                ctx.output.urls.insert(ElementLocation::new(
                    UrlParts::new(url.element),
                    url.location,
                ));
                continue;
            }

            // Parse url
            let url_parsed = match url.element.parse::<Uri>() {
                Ok(url_parsed) if url_parsed.host().is_some() => UrlParsed {
                    host: Hostname::new(url_parsed.host().unwrap()),
                    parts: url_parsed,
                },
                _ => {
                    // URL could not be parsed
                    ctx.output.urls.insert(ElementLocation::new(
                        UrlParts::new(url.element),
                        url.location,
                    ));
                    ctx.result.add_tag("R_UNPARSABLE_URL");
                    continue;
                }
            };
            let host_sld = url_parsed.host.sld_or_default();

            // Skip local and trusted domains
            if is_trusted_domain(self, host_sld, ctx.input.span_id).await {
                continue;
            }

            if let Some(ip) = url_parsed.host.ip {
                // Check IP DNSBL
                if ctx.result.rbl_ip_checks < self.core.spam.dnsbl.max_ip_checks {
                    for dnsbl in &self.core.spam.dnsbl.servers {
                        if dnsbl.scope == Element::Ip {
                            if let Some(tag) = is_dnsbl(
                                self,
                                dnsbl,
                                SpamFilterResolver::new(ctx, &IpResolver::new(ip), url.location),
                            )
                            .await
                            {
                                ctx.result.add_tag(tag);
                            }
                        }
                    }
                    ctx.result.rbl_ip_checks += 1;
                }
            } else if is_url_redirector(self, host_sld, ctx.input.span_id).await {
                // Check for redirectors
                ctx.result.add_tag("REDIRECTOR_URL");

                if !ctx.result.has_tag("URL_REDIRECTOR_NESTED") {
                    let mut redirect_count = 1;
                    let mut url_redirect = Cow::Borrowed(url.element.as_str());

                    while redirect_count <= 3 {
                        match http_get_header(
                            url_redirect.as_ref(),
                            LOCATION,
                            Duration::from_secs(5),
                        )
                        .await
                        {
                            Ok(Some(location)) => {
                                if let Ok(location_parsed) = location.parse::<Uri>() {
                                    let host =
                                        Hostname::new(location_parsed.host().unwrap_or_default());
                                    if is_url_redirector(
                                        self,
                                        host.sld_or_default(),
                                        ctx.input.span_id,
                                    )
                                    .await
                                    {
                                        url_redirect = Cow::Owned(location);
                                        redirect_count += 1;
                                        continue;
                                    } else {
                                        ctx.output.urls.insert(ElementLocation::new(
                                            UrlParts::new(location.to_lowercase())
                                                .with_parts(location_parsed, host),
                                            url.location,
                                        ));
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

            // Add URL
            ctx.output.urls.insert(ElementLocation::new(
                UrlParts::new(url.element).with_parsed(url_parsed),
                url.location,
            ));
        }

        for (el, url_parsed) in ctx.output.urls.iter().filter_map(|el| {
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
                            && matches!(self.core.dns_exists_ip(&cured_host).await, Ok(true))
                        {
                            ctx.result.add_tag("HOMOGRAPH_URL");
                        }
                    }

                    if !host.fqdn.is_single_script() {
                        ctx.result.add_tag("MIXED_CHARSET_URL");
                    }
                }

                // Check Domain DNSBL
                if ctx.result.rbl_domain_checks < self.core.spam.dnsbl.max_domain_checks {
                    for dnsbl in &self.core.spam.dnsbl.servers {
                        if matches!(dnsbl.scope, Element::Domain) {
                            if let Some(tag) = is_dnsbl(
                                self,
                                dnsbl,
                                SpamFilterResolver::new(
                                    ctx,
                                    &StringResolver(host.sld_or_default()),
                                    el.location,
                                ),
                            )
                            .await
                            {
                                ctx.result.add_tag(tag);
                            }
                        }
                    }
                    ctx.result.rbl_domain_checks += 1;
                }
            } else {
                // URL is an ip address
                ctx.result.add_tag("R_SUSPICIOUS_URL");
            }

            // Check URL DNSBL
            if ctx.result.rbl_url_checks < self.core.spam.dnsbl.max_url_checks {
                for dnsbl in &self.core.spam.dnsbl.servers {
                    if matches!(dnsbl.scope, Element::Url) {
                        if let Some(tag) = is_dnsbl(
                            self,
                            dnsbl,
                            SpamFilterResolver::new(ctx, &el.element, el.location),
                        )
                        .await
                        {
                            ctx.result.add_tag(tag);
                        }
                    }
                }
                ctx.result.rbl_url_checks += 1;
            }
        }
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

fn is_single_url<T: AsRef<str>>(tokens: &[TokenType<T>]) -> bool {
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

fn is_single_html_url<T: AsRef<str>>(html_tokens: &[HtmlToken], tokens: &[TokenType<T>]) -> bool {
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

impl PartialEq for UrlParts {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Eq for UrlParts {}

impl Hash for UrlParts {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

impl UrlParts {
    pub fn new(url: String) -> Self {
        Self {
            url,
            url_parsed: None,
        }
    }

    pub fn with_parsed(mut self, url_parsed: UrlParsed) -> Self {
        self.url_parsed = Some(url_parsed);
        self
    }

    pub fn with_parts(mut self, url_parsed: Uri, host: Hostname) -> Self {
        self.url_parsed = Some(UrlParsed {
            parts: url_parsed,
            host,
        });
        self
    }
}
