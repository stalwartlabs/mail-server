/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use compact_str::CompactString;
use mail_parser::{HeaderName, PartType, parsers::fields::thread::thread_name};
use nlp::tokenizers::types::{TokenType, TypesTokenizer};

use crate::{
    Email, Hostname, IpParts, Recipient, SpamFilterContext, SpamFilterInput, SpamFilterOutput,
    SpamFilterResult, TextPart,
    modules::html::{HEAD, HtmlToken, html_to_tokens},
};

use super::url::UrlParts;

pub trait SpamFilterInit {
    fn spam_filter_init<'x>(&self, input: SpamFilterInput<'x>) -> SpamFilterContext<'x>;
}

const POSTMASTER_ADDRESSES: [&str; 3] = ["postmaster", "mailer-daemon", "root"];

impl SpamFilterInit for Server {
    fn spam_filter_init<'x>(&self, input: SpamFilterInput<'x>) -> SpamFilterContext<'x> {
        let mut subject = "";
        let mut from = None;
        let mut reply_to = None;
        let mut recipients_to = Vec::new();
        let mut recipients_cc = Vec::new();
        let mut recipients_bcc = Vec::new();

        for header in input.message.headers() {
            match &header.name {
                HeaderName::To | HeaderName::Cc | HeaderName::Bcc => {
                    if let Some(addrs) = header.value().as_address() {
                        for addr in addrs.iter() {
                            let rcpt = Recipient {
                                email: Email::new(addr.address().unwrap_or_default()),
                                name: addr.name().and_then(|s| {
                                    let s = s.trim();
                                    if !s.is_empty() {
                                        Some(CompactString::from_str_to_lowercase(s))
                                    } else {
                                        None
                                    }
                                }),
                            };
                            if header.name == HeaderName::To {
                                recipients_to.push(rcpt);
                            } else if header.name == HeaderName::Cc {
                                recipients_cc.push(rcpt);
                            } else {
                                recipients_bcc.push(rcpt);
                            }
                        }
                    }
                }
                HeaderName::ReplyTo => {
                    reply_to = header
                        .value()
                        .as_address()
                        .and_then(|addrs| addrs.first())
                        .and_then(|addr| {
                            Some(Recipient {
                                email: Email::new(addr.address()?),
                                name: addr.name().and_then(|s| {
                                    let s = s.trim();
                                    if !s.is_empty() {
                                        Some(CompactString::from_str_to_lowercase(s))
                                    } else {
                                        None
                                    }
                                }),
                            })
                        });
                }
                HeaderName::Subject => {
                    subject = header.value().as_text().unwrap_or_default();
                }
                HeaderName::From => {
                    from = header.value().as_address().and_then(|addrs| addrs.first());
                }
                _ => {}
            }
        }

        // Tokenize subject
        let subject_tokens = TypesTokenizer::new(subject)
            .tokenize_numbers(false)
            .tokenize_urls(true)
            .tokenize_urls_without_scheme(true)
            .tokenize_emails(true)
            .map(|t| match t.word {
                TokenType::Alphabetic(s) => TokenType::Alphabetic(s.into()),
                TokenType::Alphanumeric(s) => TokenType::Alphanumeric(s.into()),
                TokenType::Integer(s) => TokenType::Integer(s.into()),
                TokenType::Other(s) => TokenType::Other(s),
                TokenType::Punctuation(s) => TokenType::Punctuation(s),
                TokenType::Space => TokenType::Space,
                TokenType::Url(url) => TokenType::Url(UrlParts::new(url)),
                TokenType::UrlNoHost(s) => TokenType::UrlNoHost(s.into()),
                TokenType::UrlNoScheme(s) => {
                    TokenType::UrlNoScheme(UrlParts::new(format!("https://{}", s.trim())))
                }
                TokenType::IpAddr(i) => TokenType::IpAddr(IpParts::new(i)),
                TokenType::Email(e) => TokenType::Email(Email::new(e)),
                TokenType::Float(s) => TokenType::Float(s.into()),
            })
            .collect::<Vec<_>>();

        // Tokenize and convert text parts
        let mut text_parts = Vec::new();
        let mut text_parts_nested = Vec::new();
        let mut message_stack = Vec::new();
        let mut message_iter = input.message.parts.iter();

        loop {
            while let Some(part) = message_iter.next() {
                let is_main_message = message_stack.is_empty();
                let text_part = match &part.body {
                    PartType::Text(text) => TextPart::Plain {
                        text_body: text.as_ref(),
                        tokens: TypesTokenizer::new(text.as_ref())
                            .tokenize_numbers(false)
                            .tokenize_urls(true)
                            .tokenize_urls_without_scheme(true)
                            .tokenize_emails(true)
                            .map(|t| match t.word {
                                TokenType::Alphabetic(s) => TokenType::Alphabetic(s.into()),
                                TokenType::Alphanumeric(s) => TokenType::Alphanumeric(s.into()),
                                TokenType::Integer(s) => TokenType::Integer(s.into()),
                                TokenType::Other(s) => TokenType::Other(s),
                                TokenType::Punctuation(s) => TokenType::Punctuation(s),
                                TokenType::Space => TokenType::Space,
                                TokenType::Url(url) => TokenType::Url(UrlParts::new(url)),
                                TokenType::UrlNoHost(s) => TokenType::UrlNoHost(s.into()),
                                TokenType::UrlNoScheme(s) => TokenType::UrlNoScheme(UrlParts::new(
                                    format!("https://{}", s.trim()),
                                )),
                                TokenType::IpAddr(i) => TokenType::IpAddr(IpParts::new(i)),
                                TokenType::Email(e) => TokenType::Email(Email::new(e)),
                                TokenType::Float(s) => TokenType::Float(s.into()),
                            })
                            .collect::<Vec<_>>(),
                    },
                    PartType::Html(html) => {
                        let html_tokens = html_to_tokens(html);
                        let text_body_len = html_tokens
                            .iter()
                            .filter_map(|t| match t {
                                HtmlToken::Text { text } => text.len().into(),
                                _ => None,
                            })
                            .sum();
                        let mut text_body = String::with_capacity(text_body_len);
                        let mut in_head = false;
                        for token in &html_tokens {
                            match token {
                                HtmlToken::StartTag { name: HEAD, .. } => {
                                    in_head = true;
                                }
                                HtmlToken::EndTag { name: HEAD } => {
                                    in_head = false;
                                }
                                HtmlToken::Text { text } if !in_head => {
                                    if !text_body.is_empty()
                                        && !text_body.ends_with(' ')
                                        && !text.starts_with(' ')
                                    {
                                        text_body.push(' ');
                                    }
                                    text_body.push_str(text)
                                }
                                _ => {}
                            }
                        }

                        TextPart::Html {
                            tokens: TypesTokenizer::new(&text_body)
                                .tokenize_numbers(false)
                                .tokenize_urls(true)
                                .tokenize_urls_without_scheme(true)
                                .tokenize_emails(true)
                                .map(|t| match t.word {
                                    TokenType::Alphabetic(s) => {
                                        TokenType::Alphabetic(s.to_string().into())
                                    }
                                    TokenType::Alphanumeric(s) => {
                                        TokenType::Alphanumeric(s.to_string().into())
                                    }
                                    TokenType::Integer(s) => {
                                        TokenType::Integer(s.to_string().into())
                                    }
                                    TokenType::Other(s) => TokenType::Other(s),
                                    TokenType::Punctuation(s) => TokenType::Punctuation(s),
                                    TokenType::Space => TokenType::Space,
                                    TokenType::Url(url) => {
                                        TokenType::Url(UrlParts::new(url.to_string()))
                                    }
                                    TokenType::UrlNoHost(s) => {
                                        TokenType::UrlNoHost(s.to_string().into())
                                    }
                                    TokenType::UrlNoScheme(s) => TokenType::UrlNoScheme(
                                        UrlParts::new(format!("https://{}", s.trim())),
                                    ),
                                    TokenType::IpAddr(i) => {
                                        TokenType::IpAddr(IpParts::new(i.to_string()))
                                    }
                                    TokenType::Email(e) => TokenType::Email(Email::new(e)),
                                    TokenType::Float(s) => TokenType::Float(s.to_string().into()),
                                })
                                .collect::<Vec<_>>(),
                            html_tokens,
                            text_body,
                        }
                    }
                    PartType::Message(message) => {
                        message_stack.push(message_iter);
                        message_iter = message.parts.iter();
                        TextPart::None
                    }
                    _ => TextPart::None,
                };

                if is_main_message {
                    text_parts.push(text_part);
                } else if !matches!(text_part, TextPart::None) {
                    text_parts_nested.push(text_part);
                }
            }

            if let Some(iter) = message_stack.pop() {
                message_iter = iter;
            } else {
                break;
            }
        }
        text_parts.extend(text_parts_nested);

        let subject_thread = thread_name(subject).to_string();
        let env_from_addr = Email::new(input.env_from);
        SpamFilterContext {
            output: SpamFilterOutput {
                ehlo_host: Hostname::new(input.ehlo_domain.unwrap_or("unknown")),
                iprev_ptr: input.iprev_result.and_then(|r| {
                    r.ptr.as_ref().and_then(|ptr| ptr.first()).map(|ptr| {
                        CompactString::from_str_to_lowercase(ptr.strip_suffix('.').unwrap_or(ptr))
                    })
                }),
                env_from_postmaster: env_from_addr.address.is_empty()
                    || POSTMASTER_ADDRESSES.contains(&env_from_addr.local_part.as_str()),
                env_from_addr,
                env_to_addr: input
                    .env_rcpt_to
                    .iter()
                    .map(|rcpt| Email::new(rcpt))
                    .collect(),
                from: Recipient {
                    email: Email::new(from.and_then(|f| f.address()).unwrap_or_default()),
                    name: from
                        .and_then(|f| f.name())
                        .map(CompactString::from_str_to_lowercase),
                },
                reply_to,
                subject_thread_lc: subject_thread.trim().to_lowercase(),
                subject_thread,
                subject_lc: subject.trim().to_lowercase(),
                subject: subject.to_string(),
                subject_tokens,
                recipients_to,
                recipients_cc,
                recipients_bcc,
                text_parts,
                ips: Default::default(),
                emails: Default::default(),
                urls: Default::default(),
                domains: Default::default(),
            },
            input,
            result: SpamFilterResult::default(),
        }
    }
}
