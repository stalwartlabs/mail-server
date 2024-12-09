use std::{borrow::Cow, future::Future, time::Duration};

use common::Server;
use common::{config::spamfilter::Target, scripts::functions::unicode::CharUtils};
use hyper::{
    header::{HeaderName, LOCATION},
    Uri,
};
use nlp::tokenizers::types::TokenType;
use reqwest::redirect::Policy;
use unicode_security::MixedScript;

use crate::modules::dnsbl::is_dnsbl;
use crate::modules::remote_list::is_in_remote_list;
use crate::{
    modules::html::{HtmlToken, A, HREF},
    Hostname, SpamFilterContext, TextPart,
};

pub trait SpamFilterAnalyzeUrl: Sync + Send {
    fn spam_filter_analyze_url(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeUrl for Server {
    async fn spam_filter_analyze_url(&self, ctx: &mut SpamFilterContext<'_>) {
        for (part_id, part) in ctx.output.text_parts.iter().enumerate() {
            if ctx.input.message.text_body.contains(&part_id)
                || ctx.input.message.html_body.contains(&part_id)
            {
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
                    break;
                }
            }
        }

        for url in &ctx.output.urls {
            for ch in url.chars() {
                if ch.is_zwsp() {
                    ctx.result.add_tag("ZERO_WIDTH_SPACE_URL");
                }

                if ch.is_obscured() {
                    ctx.result.add_tag("R_SUSPICIOUS_URL");
                }
            }

            // Skip non-URLs such as 'data:' and 'mailto:'
            if !url.contains("://") {
                continue;
            }

            // Parse url
            let url_parsed = match url.parse::<Uri>() {
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
            if self.core.spam.list_trusted_domains.contains(host_sld)
                || self
                    .core
                    .storage
                    .directory
                    .is_local_domain(host_sld)
                    .await
                    .unwrap_or_default()
            {
                continue;
            }

            // Check for redirectors
            let mut redirected_urls = Vec::new();
            if host.ip.is_none() && self.core.spam.list_url_redirectors.contains(host_sld) {
                ctx.result.add_tag("REDIRECTOR_URL");

                let mut redirect_count = 0;
                let mut url_redirect = Cow::Borrowed(url);

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
                                    let location = location.to_lowercase();
                                    if !ctx.output.urls.contains(&location) {
                                        redirected_urls.push((
                                            Cow::Owned(location),
                                            location_parsed,
                                            host,
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

            for (url, url_parsed, host) in [(Cow::Borrowed(url), url_parsed, host)]
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
                    if matches!(remote.target, Target::Url)
                        && is_in_remote_list(self, remote, url.as_ref(), ctx.input.span_id).await
                    {
                        ctx.result.add_tag(&remote.tag);
                    }
                }

                // Check DNSBL
                for dnsbl in &self.core.spam.dnsbls {
                    if matches!(dnsbl.target, Target::Url) {
                        if let Some(tag) =
                            is_dnsbl(self, dnsbl, url.as_ref(), ctx.input.span_id).await
                        {
                            ctx.result.add_tag(tag);
                        }
                    }
                }
            }
        }
    }
}

async fn http_get_header(
    url: &str,
    header: HeaderName,
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
        if matches!(token, HtmlToken::StartTag { name, attributes } if *name == A && attributes.iter().any(|(k, _)| *k == HREF))
        {
            url_count += 1;
        }
    }

    url_count == 1
}
