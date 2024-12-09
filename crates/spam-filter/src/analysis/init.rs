use std::collections::HashSet;

use common::Server;
use mail_parser::{parsers::fields::thread::thread_name, HeaderName, PartType};
use nlp::tokenizers::types::{TokenType, TypesTokenizer};

use crate::{
    modules::html::{html_to_tokens, HtmlToken, HREF, SRC},
    Email, Hostname, Recipient, SpamFilterContext, SpamFilterInput, SpamFilterOutput,
    SpamFilterResult, TextPart,
};

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
                                        Some(s.to_lowercase())
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
                                        Some(s.to_lowercase())
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
            .map(|t| t.word)
            .collect::<Vec<_>>();
        let subject = subject.to_lowercase();

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
                            .map(|t| t.word)
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
                        for token in &html_tokens {
                            if let HtmlToken::Text { text } = token {
                                if !text_body.is_empty()
                                    && !text_body.ends_with(' ')
                                    && text.starts_with(' ')
                                {
                                    text_body.push(' ');
                                }
                                text_body.push_str(text)
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
                                        TokenType::Alphabetic(s.to_string())
                                    }
                                    TokenType::Alphanumeric(s) => {
                                        TokenType::Alphanumeric(s.to_string())
                                    }
                                    TokenType::Integer(s) => TokenType::Integer(s.to_string()),
                                    TokenType::Other(s) => TokenType::Other(s),
                                    TokenType::Punctuation(s) => TokenType::Punctuation(s),
                                    TokenType::Space => TokenType::Space,
                                    TokenType::Url(s) => TokenType::Url(s.to_string()),
                                    TokenType::UrlNoScheme(s) => {
                                        TokenType::UrlNoScheme(s.to_string())
                                    }
                                    TokenType::UrlNoHost(s) => TokenType::UrlNoHost(s.to_string()),
                                    TokenType::IpAddr(s) => TokenType::IpAddr(s.to_string()),
                                    TokenType::Email(s) => TokenType::Email(s.to_string()),
                                    TokenType::Float(s) => TokenType::Float(s.to_string()),
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

        // Extract URLs
        let mut urls: HashSet<String> =
            HashSet::from_iter(subject_tokens.iter().filter_map(|t| t.url_lowercase(false)));
        for part in &text_parts {
            match part {
                TextPart::Plain { tokens, .. } => {
                    urls.extend(tokens.iter().filter_map(|t| t.url_lowercase(false)));
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
                                        urls.insert(value.trim().to_lowercase());
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    urls.extend(tokens.iter().filter_map(|t| t.url_lowercase(false)));
                }
                TextPart::None => {}
            }
        }

        let env_from_addr = Email::new(input.env_from);
        SpamFilterContext {
            output: SpamFilterOutput {
                ehlo_host: Hostname::new(input.ehlo_domain),
                iprev_ptr: input
                    .iprev_result
                    .ptr
                    .as_ref()
                    .and_then(|ptr| ptr.first())
                    .map(|ptr| ptr.strip_suffix('.').unwrap_or(ptr).to_lowercase()),
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
                    name: from.and_then(|f| f.name()).map(|s| s.to_lowercase()),
                },
                reply_to,
                subject_thread: thread_name(&subject).to_string(),
                subject,
                subject_tokens,
                recipients_to,
                recipients_cc,
                recipients_bcc,
                text_parts,
                urls,
            },
            input,
            result: SpamFilterResult {
                tags: Default::default(),
            },
        }
    }
}

/*

use std::future::Future;

use common::Server;

use crate::SpamFilterContext;

pub trait SpamFilterAnalyze!: Sync + Send {
    fn spam_filter_analyze_*(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyze! for Server {
    async fn spam_filter_analyze_*(&self, ctx: &mut SpamFilterContext<'_>) {
        todo!()
    }
}


*/
