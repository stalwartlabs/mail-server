use std::collections::HashSet;
use std::{borrow::Cow, future::Future, time::Duration};

use common::config::spamfilter::{Element, Location};
use common::expr::functions::ResolveVariable;
use common::expr::Variable;
use common::scripts::functions::unicode::CharUtils;
use common::Server;
use hyper::{header::LOCATION, Uri};
use mail_parser::HeaderName;
use nlp::tokenizers::types::TokenType;
use reqwest::redirect::Policy;
use unicode_security::MixedScript;

use crate::modules::dnsbl::is_dnsbl;
use crate::modules::html::SRC;
use crate::modules::remote_list::is_in_remote_list;
use crate::{
    modules::html::{HtmlToken, A, HREF},
    Hostname, SpamFilterContext, TextPart,
};

use super::{is_trusted_domain, ElementLocation, SpamFilterResolver};

pub trait SpamFilterAnalyzeUrl: Sync + Send {
    fn spam_filter_analyze_url(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeUrl for Server {
    async fn spam_filter_analyze_url(&self, ctx: &mut SpamFilterContext<'_>) {
        // Extract URLs
        let mut urls: HashSet<ElementLocation<String>> = HashSet::from_iter(
            ctx.output
                .subject_tokens
                .iter()
                .filter_map(|t| t.url_lowercase(false))
                .map(|url| ElementLocation::new(url, HeaderName::Subject)),
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

        for url in &urls {
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
                continue;
            }

            // Parse url
            let url_parsed = match url.element.parse::<Uri>() {
                Ok(url) if url.host().is_some() => url,
                _ => {
                    // URL could not be parsed
                    ctx.result.add_tag("R_SUSPICIOUS_URL");
                    continue;
                }
            };
            let host = Hostname::new(url_parsed.host().unwrap());
            let host_sld = host.sld_or_default();

            // Skip local and trusted domains
            if is_trusted_domain(self, host_sld, ctx.input.span_id).await {
                continue;
            }

            let mut redirected_urls = Vec::new();
            if let Some(ip) = host.ip {
                // Check IP DNSBL
                if ctx.result.rbl_ip_checks < self.core.spam.max_rbl_ip_checks {
                    for dnsbl in &self.core.spam.dnsbls {
                        if dnsbl.element == Element::Ip
                            && dnsbl.element_location.contains(&url.location)
                        {
                            if let Some(tag) =
                                is_dnsbl(self, dnsbl, SpamFilterResolver::new(ctx, &ip)).await
                            {
                                ctx.result.add_tag(tag);
                            }
                        }
                    }
                    ctx.result.rbl_ip_checks += 1;
                }
            } else if self.core.spam.list_url_redirectors.contains(host_sld) {
                // Check for redirectors
                ctx.result.add_tag("REDIRECTOR_URL");

                let mut redirect_count = 0;
                let mut url_redirect = Cow::Borrowed(url.element.as_str());

                while redirect_count <= 0 {
                    match http_get_header(url_redirect.as_ref(), LOCATION, Duration::from_secs(5))
                        .await
                    {
                        Ok(Some(location)) => {
                            if let Ok(location_parsed) = location.parse::<Uri>() {
                                let host =
                                    Hostname::new(location_parsed.host().unwrap_or_default());
                                if self
                                    .core
                                    .spam
                                    .list_url_redirectors
                                    .contains(host.sld_or_default())
                                {
                                    url_redirect = Cow::Owned(location);
                                    redirect_count += 1;
                                    continue;
                                } else {
                                    let new_url = ElementLocation::new(
                                        location.to_lowercase(),
                                        url.location.clone(),
                                    );
                                    if !urls.contains(&new_url) {
                                        redirected_urls.push((
                                            Cow::Owned(new_url.element),
                                            location_parsed,
                                            host,
                                            new_url.location,
                                        ));
                                    }
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

                if redirect_count > 5 {
                    ctx.result.add_tag("URL_REDIRECTOR_NESTED");
                }
            }

            for (url, url_parsed, host, location) in [(
                Cow::Borrowed(url.element.as_str()),
                url_parsed,
                host,
                url.location.clone(),
            )]
            .into_iter()
            .chain(redirected_urls.into_iter())
            {
                let query = url_parsed
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or_default();
                if host.ip.is_none() {
                    if !host.fqdn.is_ascii() {
                        if let Ok(cured_host) =
                            decancer::cure(&host.fqdn, decancer::Options::default())
                        {
                            let cured_host = cured_host.to_string();
                            if cured_host != host.fqdn
                                && matches!(self.core.dns_exists_ip(&cured_host).await, Ok(true))
                            {
                                ctx.result.add_tag("HOMOGRAPH_URL");
                            }

                            if !cured_host.is_single_script() {
                                ctx.result.add_tag("MIXED_CHARSET_URL");
                            }
                        }
                    } else if matches!(host.sld.as_deref(), Some("googleusercontent.com"))
                        && query.starts_with("/proxy/")
                    {
                        ctx.result.add_tag("HAS_GUC_PROXY_URI");
                    } else if host.fqdn.ends_with("firebasestorage.googleapis.com") {
                        ctx.result.add_tag("HAS_GOOGLE_FIREBASE_URL");
                    } else if host.sld_or_default().starts_with("google.") && query.contains("url?")
                    {
                        ctx.result.add_tag("HAS_GOOGLE_REDIR");
                    }

                    if host.fqdn.contains("ipfs.")
                        || (query.contains("/ipfs") && query.contains("/qm"))
                    {
                        // InterPlanetary File System (IPFS) gateway URL, likely malicious
                        ctx.result.add_tag("HAS_IPFS_GATEWAY_URL");
                    } else if host.fqdn.ends_with(".onion") {
                        // Onion URL
                        ctx.result.add_tag("HAS_ONION_URI");
                    }

                    // Check Domain DNSBL
                    if ctx.result.rbl_domain_checks < self.core.spam.max_rbl_domain_checks {
                        for dnsbl in &self.core.spam.dnsbls {
                            if matches!(dnsbl.element, Element::Domain)
                                && dnsbl.element_location.contains(&location)
                            {
                                if let Some(tag) = is_dnsbl(
                                    self,
                                    dnsbl,
                                    SpamFilterResolver::new(ctx, &host.sld_or_default()),
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

                if query.starts_with("/wp-") {
                    // Contains WordPress URIs
                    ctx.result.add_tag("HAS_WP_URI");

                    if query.starts_with("/wp-content") || query.starts_with("/wp-includes") {
                        // URL that is pointing to a compromised WordPress installation
                        ctx.result.add_tag("WP_COMPROMISED");
                    }
                }

                if query.contains("/../")
                    && !query.contains("/.well-known")
                    && !query.contains("/.well_known")
                {
                    // Message contains URI with a hidden path
                    ctx.result.add_tag("URI_HIDDEN_PATH");
                }

                // Check remote lists
                for remote in &self.core.spam.remote_lists {
                    if matches!(remote.element, Element::Url)
                        && remote.element_location.contains(&location)
                        && is_in_remote_list(self, remote, url.as_ref(), ctx.input.span_id).await
                    {
                        ctx.result.add_tag(&remote.tag);
                    }
                }

                // Check URL DNSBL
                if ctx.result.rbl_url_checks < self.core.spam.max_rbl_url_checks {
                    for dnsbl in &self.core.spam.dnsbls {
                        if matches!(dnsbl.element, Element::Url)
                            && dnsbl.element_location.contains(&location)
                        {
                            if let Some(tag) = is_dnsbl(
                                self,
                                dnsbl,
                                SpamFilterResolver::new(
                                    ctx,
                                    &UriHost::new(&url, &url_parsed, &host),
                                ),
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
}

async fn http_get_header(
    url: &str,
    header: hyper::header::HeaderName,
    timeout: Duration,
) -> trc::Result<Option<String>> {
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

struct UriHost<'x> {
    full_url: &'x str,
    url: &'x Uri,
    host: &'x Hostname,
}

pub const V_URL_FULL: u32 = 0;
pub const V_URL_PATH_QUERY: u32 = 1;
pub const V_URL_PATH: u32 = 2;
pub const V_URL_QUERY: u32 = 3;
pub const V_URL_SCHEME: u32 = 4;
pub const V_URL_AUTHORITY: u32 = 5;
pub const V_URL_HOST: u32 = 6;
pub const V_URL_HOST_SLD: u32 = 7;
pub const V_URL_PORT: u32 = 8;

impl ResolveVariable for UriHost<'_> {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        match variable {
            V_URL_FULL => Variable::String(self.full_url.into()),
            V_URL_PATH_QUERY => Variable::String(
                self.url
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or_default()
                    .into(),
            ),
            V_URL_PATH => Variable::String(self.url.path().into()),
            V_URL_QUERY => Variable::String(self.url.query().unwrap_or_default().into()),
            V_URL_SCHEME => Variable::String(self.url.scheme_str().unwrap_or_default().into()),
            V_URL_AUTHORITY => Variable::String(
                self.url
                    .authority()
                    .map(|a| a.as_str())
                    .unwrap_or_default()
                    .into(),
            ),
            V_URL_HOST => Variable::String(self.host.fqdn.as_str().into()),
            V_URL_HOST_SLD => Variable::String(self.host.sld_or_default().into()),
            V_URL_PORT => Variable::Integer(self.url.port_u16().unwrap_or(0) as _),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

impl<'x> UriHost<'x> {
    pub fn new(full_url: &'x str, url: &'x Uri, host: &'x Hostname) -> Self {
        Self {
            full_url,
            url,
            host,
        }
    }
}
