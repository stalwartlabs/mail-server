/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::Server;
use hyper::Uri;
use mail_parser::MimeHeaders;
use nlp::tokenizers::types::{TokenType, TypesTokenizer};

use crate::{Hostname, SpamFilterContext, TextPart, modules::html::*};

pub trait SpamFilterAnalyzeHtml: Sync + Send {
    fn spam_filter_analyze_html(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

#[derive(Debug)]
struct Href {
    url_parsed: Option<Uri>,
    host: Option<Hostname>,
}

impl SpamFilterAnalyzeHtml for Server {
    async fn spam_filter_analyze_html(&self, ctx: &mut SpamFilterContext<'_>) {
        // Message only has text/html MIME parts
        if ctx.input.message.content_type().is_some_and(|ct| {
            ct.ctype().eq_ignore_ascii_case("text")
                && ct
                    .subtype()
                    .unwrap_or_default()
                    .eq_ignore_ascii_case("html")
        }) {
            ctx.result.add_tag("MIME_HTML_ONLY");
        }

        for (part_id, part) in ctx.output.text_parts.iter().enumerate() {
            let part_id = part_id as u32;
            let is_body_part = ctx.input.message.text_body.contains(&part_id)
                || ctx.input.message.html_body.contains(&part_id);

            let (html_tokens, tokens) = if let TextPart::Html {
                html_tokens,
                tokens,
                ..
            } = part
            {
                (html_tokens, tokens)
            } else {
                continue;
            };

            let mut has_link_to_img = false;
            let mut last_href: Option<Href> = None;
            let mut html_img_words = 0;
            let mut in_head: i32 = 0;
            let mut in_body: i32 = 0;

            for token in html_tokens {
                match token {
                    HtmlToken::StartTag {
                        name,
                        attributes,
                        is_self_closing,
                    } => match *name {
                        A => {
                            if let Some(attr) = attributes.iter().find_map(|(attr, value)| {
                                if *attr == HREF {
                                    value.as_deref()
                                } else {
                                    None
                                }
                            }) {
                                let url = attr.trim().to_lowercase();
                                let url_parsed = url.parse::<Uri>().ok();
                                let href = Href {
                                    host: url_parsed
                                        .as_ref()
                                        .and_then(|uri| uri.host().map(Hostname::new)),
                                    url_parsed,
                                };

                                if is_body_part
                                    && attr.starts_with("data:")
                                    && attr.contains(";base64,")
                                {
                                    // Has Data URI encoding
                                    ctx.result.add_tag("HAS_DATA_URI");
                                    if attr.contains("text/") {
                                        //  Uses Data URI encoding to obfuscate plain or HTML in base64
                                        ctx.result.add_tag("DATA_URI_OBFU");
                                    }
                                } else if href.host.as_ref().is_some_and(|h| h.ip.is_some()) {
                                    // HTML anchor points to an IP address
                                    ctx.result.add_tag("HTTP_TO_IP");
                                }

                                if !*is_self_closing {
                                    last_href = Some(href);
                                }
                            }
                        }
                        IMG if is_body_part => {
                            let mut img_width = 800;
                            let mut img_height = 600;

                            for (attr, value) in attributes {
                                if let Some(value) =
                                    value.as_deref().map(|v| v.trim()).filter(|v| !v.is_empty())
                                {
                                    let dimension = match *attr {
                                        WIDTH => &mut img_width,
                                        HEIGHT => &mut img_height,
                                        SRC => {
                                            let src = value.to_ascii_lowercase();
                                            if src.starts_with("data:") && src.contains(";base64,")
                                            {
                                                // Has Data URI encoding
                                                ctx.result.add_tag("HAS_DATA_URI");
                                            } else if src.starts_with("https://")
                                                || src.starts_with("http://")
                                            {
                                                // Has external image
                                                ctx.result.add_tag("HAS_EXTERNAL_IMG");
                                            }
                                            continue;
                                        }
                                        _ => {
                                            continue;
                                        }
                                    };
                                    if let Some(pct) = value.strip_suffix('%') {
                                        if let Ok(pct) = pct.trim().parse::<u64>() {
                                            *dimension = (*dimension * pct) / 100;
                                        }
                                    } else if let Ok(value) = value.parse::<u64>() {
                                        *dimension = value;
                                    }
                                }
                            }
                            let dimensions = img_width + img_height;

                            if last_href.is_some() {
                                if dimensions >= 210 {
                                    ctx.result.add_tag("HAS_LINK_TO_LARGE_IMG");
                                    has_link_to_img = true;
                                } else {
                                    ctx.result.add_tag("HAS_LINK_TO_IMG");
                                }
                            }

                            if dimensions > 100 {
                                // We assume that a single picture 100x200 contains approx 3 words of text
                                html_img_words += dimensions / 100;
                            }
                        }
                        META => {
                            let mut has_equiv_refresh = false;
                            let mut has_content_url = false;

                            for (attr, value) in attributes {
                                if let Some(value) =
                                    value.as_deref().map(|v| v.trim()).filter(|v| !v.is_empty())
                                {
                                    if *attr == HTTP_EQUIV {
                                        if value.eq_ignore_ascii_case("refresh") {
                                            has_equiv_refresh = true;
                                        }
                                    } else if *attr == CONTENT
                                        && value.to_ascii_lowercase().contains("url=")
                                    {
                                        has_content_url = true;
                                    }
                                }
                            }

                            if has_equiv_refresh && has_content_url {
                                // HTML meta refresh tag
                                ctx.result.add_tag("HTML_META_REFRESH_URL");
                            }
                        }
                        LINK if is_body_part => {
                            let mut has_rel_style = false;
                            let mut has_href_css = false;

                            for (attr, value) in attributes {
                                if let Some(value) =
                                    value.as_deref().map(|v| v.trim()).filter(|v| !v.is_empty())
                                {
                                    if *attr == REL {
                                        if value.to_ascii_lowercase().contains("stylesheet") {
                                            has_rel_style = true;
                                        }
                                    } else if *attr == HREF
                                        && value.to_ascii_lowercase().contains(".css")
                                    {
                                        has_href_css = true;
                                    }
                                }
                            }

                            if has_rel_style || has_href_css {
                                // Has external CSS
                                ctx.result.add_tag("EXT_CSS");
                            }
                        }
                        HEAD if !*is_self_closing => {
                            in_head += 1;
                        }
                        BODY if !*is_self_closing => {
                            in_body += 1;
                        }
                        _ => {}
                    },
                    HtmlToken::EndTag { name } => match *name {
                        A => {
                            last_href = None;
                        }
                        HEAD => {
                            in_head -= 1;
                        }
                        BODY => {
                            in_body -= 1;
                        }
                        _ => (),
                    },
                    HtmlToken::Text { text } if in_head == 0 => {
                        if let Some((href_url, href_host)) = last_href
                            .as_ref()
                            .and_then(|href| Some((href.url_parsed.as_ref()?, href.host.as_ref()?)))
                        {
                            for token in TypesTokenizer::new(text.as_ref())
                                .tokenize_numbers(false)
                                .tokenize_urls(true)
                                .tokenize_urls_without_scheme(true)
                                .tokenize_emails(true)
                            {
                                let text_url = match token.word {
                                    TokenType::Url(url) => url.to_lowercase(),
                                    TokenType::UrlNoScheme(url) => {
                                        format!("http://{}", url.to_lowercase())
                                    }
                                    _ => continue,
                                };
                                let text_url_parsed =
                                    if let Ok(text_url_parsed) = text_url.parse::<Uri>() {
                                        text_url_parsed
                                    } else {
                                        continue;
                                    };

                                if href_url.scheme().map(|s| s.as_str()).unwrap_or_default()
                                    == "http"
                                    && text_url_parsed
                                        .scheme()
                                        .map(|s| s.as_str())
                                        .unwrap_or_default()
                                        == "https"
                                {
                                    // The anchor text contains a distinct scheme compared to the target URL
                                    ctx.result.add_tag("HTTP_TO_HTTPS");
                                }

                                if let Some(text_url_host) = text_url_parsed.host() {
                                    let text_url_host = Hostname::new(text_url_host);

                                    if text_url_host.sld_or_default() != href_host.sld_or_default()
                                    {
                                        // The anchor text contains a different domain than the target URL
                                        ctx.result.add_tag("PHISHING");
                                    }
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }

            if is_body_part {
                if in_head != 0 || in_body != 0 {
                    // HTML tags are not properly closed
                    ctx.result.add_tag("HTML_UNBALANCED_TAG");
                }

                let mut html_words = 0;
                let mut html_uris = 0;
                let mut html_text_chars = 0;

                for token in tokens {
                    match token {
                        TokenType::Alphabetic(s) | TokenType::Alphanumeric(s) => {
                            html_words += 1;
                            html_text_chars += s.len();
                        }
                        TokenType::Email(s) => {
                            html_words += 1;
                            html_text_chars += s.address.len();
                        }
                        TokenType::Url(_) | TokenType::UrlNoScheme(_) => {
                            html_uris += 1;
                        }
                        _ => (),
                    }
                }

                match html_text_chars {
                    0..1024 => {
                        ctx.result.add_tag("HTML_SHORT_1");
                    }
                    1024..1536 => {
                        ctx.result.add_tag("HTML_SHORT_2");
                    }
                    1536..2048 => {
                        ctx.result.add_tag("HTML_SHORT_3");
                    }
                    _ => (),
                }

                if (!has_link_to_img || html_text_chars >= 2048)
                    && (html_img_words as f64 / (html_words as f64 + html_img_words as f64) > 0.5)
                {
                    // Message contains more images than text
                    ctx.result.add_tag("HTML_TEXT_IMG_RATIO");
                }

                if html_uris > 0 && html_words == 0 {
                    // Message only contains URIs in HTML
                    ctx.result.add_tag("BODY_URI_ONLY");
                }
            }
        }
    }
}
