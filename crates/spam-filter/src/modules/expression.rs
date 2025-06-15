/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    config::spamfilter::*,
    expr::{StringCow, Variable, functions::ResolveVariable},
};
use compact_str::{CompactString, ToCompactString, format_compact};
use mail_parser::{Header, HeaderValue};
use nlp::tokenizers::types::TokenType;

use crate::{Recipient, SpamFilterContext, TextPart, analysis::url::UrlParts};

pub(crate) struct SpamFilterResolver<'x, T: ResolveVariable> {
    pub ctx: &'x SpamFilterContext<'x>,
    pub item: &'x T,
    pub location: Location,
}

impl<'x, T: ResolveVariable> SpamFilterResolver<'x, T> {
    pub fn new(ctx: &'x SpamFilterContext<'x>, item: &'x T, location: Location) -> Self {
        Self {
            ctx,
            item,
            location,
        }
    }
}

impl<T: ResolveVariable> ResolveVariable for SpamFilterResolver<'_, T> {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        match variable {
            0..100 => self.item.resolve_variable(variable),
            V_SPAM_REMOTE_IP => self.ctx.input.remote_ip.to_compact_string().into(),
            V_SPAM_REMOTE_IP_PTR => self
                .ctx
                .output
                .iprev_ptr
                .as_deref()
                .unwrap_or_default()
                .into(),
            V_SPAM_EHLO_DOMAIN => self.ctx.output.ehlo_host.fqdn.as_str().into(),
            V_SPAM_AUTH_AS => self.ctx.input.authenticated_as.unwrap_or_default().into(),
            V_SPAM_ASN => self.ctx.input.asn.unwrap_or_default().into(),
            V_SPAM_COUNTRY => self.ctx.input.country.unwrap_or_default().into(),
            V_SPAM_IS_TLS => self.ctx.input.is_tls.into(),
            V_SPAM_ENV_FROM => self.ctx.output.env_from_addr.address.as_str().into(),
            V_SPAM_ENV_FROM_LOCAL => self.ctx.output.env_from_addr.local_part.as_str().into(),
            V_SPAM_ENV_FROM_DOMAIN => self
                .ctx
                .output
                .env_from_addr
                .domain_part
                .fqdn
                .as_str()
                .into(),
            V_SPAM_ENV_TO => self
                .ctx
                .output
                .env_to_addr
                .iter()
                .map(|e| Variable::from(e.address.as_str()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_FROM => self.ctx.output.from.email.address.as_str().into(),
            V_SPAM_FROM_NAME => self
                .ctx
                .output
                .from
                .name
                .as_deref()
                .unwrap_or_default()
                .into(),
            V_SPAM_FROM_LOCAL => self.ctx.output.from.email.local_part.as_str().into(),
            V_SPAM_FROM_DOMAIN => self.ctx.output.from.email.domain_part.fqdn.as_str().into(),
            V_SPAM_REPLY_TO => self
                .ctx
                .output
                .reply_to
                .as_ref()
                .map(|r| r.email.address.as_str())
                .unwrap_or_default()
                .into(),
            V_SPAM_REPLY_TO_NAME => self
                .ctx
                .output
                .reply_to
                .as_ref()
                .and_then(|r| r.name.as_deref())
                .unwrap_or_default()
                .into(),
            V_SPAM_REPLY_TO_LOCAL => self
                .ctx
                .output
                .reply_to
                .as_ref()
                .map(|r| r.email.local_part.as_str())
                .unwrap_or_default()
                .into(),
            V_SPAM_REPLY_TO_DOMAIN => self
                .ctx
                .output
                .reply_to
                .as_ref()
                .map(|r| r.email.domain_part.fqdn.as_str())
                .unwrap_or_default()
                .into(),
            V_SPAM_TO => self
                .ctx
                .output
                .recipients_to
                .iter()
                .map(|r| Variable::from(r.email.address.as_str()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_TO_NAME => self
                .ctx
                .output
                .recipients_to
                .iter()
                .filter_map(|r| Variable::from(r.name.as_deref()?).into())
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_TO_LOCAL => self
                .ctx
                .output
                .recipients_to
                .iter()
                .map(|r| Variable::from(r.email.local_part.as_str()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_TO_DOMAIN => self
                .ctx
                .output
                .recipients_to
                .iter()
                .map(|r| Variable::from(r.email.domain_part.fqdn.as_str()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_CC => self
                .ctx
                .output
                .recipients_cc
                .iter()
                .map(|r| Variable::from(r.email.address.as_str()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_CC_NAME => self
                .ctx
                .output
                .recipients_cc
                .iter()
                .filter_map(|r| Variable::from(r.name.as_deref()?).into())
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_CC_LOCAL => self
                .ctx
                .output
                .recipients_cc
                .iter()
                .map(|r| Variable::from(r.email.local_part.as_str()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_CC_DOMAIN => self
                .ctx
                .output
                .recipients_cc
                .iter()
                .map(|r| Variable::from(r.email.domain_part.fqdn.as_str()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_BCC => self
                .ctx
                .output
                .recipients_bcc
                .iter()
                .map(|r| Variable::from(r.email.address.as_str()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_BCC_NAME => self
                .ctx
                .output
                .recipients_bcc
                .iter()
                .filter_map(|r| Variable::from(r.name.as_deref()?).into())
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_BCC_LOCAL => self
                .ctx
                .output
                .recipients_bcc
                .iter()
                .map(|r| Variable::from(r.email.local_part.as_str()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_BCC_DOMAIN => self
                .ctx
                .output
                .recipients_bcc
                .iter()
                .map(|r| Variable::from(r.email.domain_part.fqdn.as_str()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_BODY_TEXT => self.ctx.text_body().unwrap_or_default().into(),
            V_SPAM_BODY_HTML => self
                .ctx
                .input
                .message
                .html_body
                .first()
                .and_then(|idx| self.ctx.output.text_parts.get(*idx as usize))
                .map(|part| {
                    if let TextPart::Html { text_body, .. } = part {
                        text_body.as_str()
                    } else {
                        ""
                    }
                })
                .unwrap_or_default()
                .into(),
            V_SPAM_BODY_RAW => Variable::from(CompactString::from_utf8_lossy(
                self.ctx.input.message.raw_message(),
            )),
            V_SPAM_SUBJECT => self.ctx.output.subject_lc.as_str().into(),
            V_SPAM_SUBJECT_THREAD => self.ctx.output.subject_thread_lc.as_str().into(),
            V_SPAM_LOCATION => self.location.as_str().into(),
            V_WORDS_SUBJECT => self
                .ctx
                .output
                .subject_tokens
                .iter()
                .filter_map(|w| match w {
                    TokenType::Alphabetic(w)
                    | TokenType::Alphanumeric(w)
                    | TokenType::Integer(w)
                    | TokenType::Float(w) => Some(Variable::from(w.as_ref())),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .into(),
            V_WORDS_BODY => self
                .ctx
                .input
                .message
                .html_body
                .first()
                .and_then(|idx| self.ctx.output.text_parts.get(*idx as usize))
                .map(|part| match part {
                    TextPart::Plain { tokens, .. } | TextPart::Html { tokens, .. } => tokens
                        .iter()
                        .filter_map(|w| match w {
                            TokenType::Alphabetic(w)
                            | TokenType::Alphanumeric(w)
                            | TokenType::Integer(w)
                            | TokenType::Float(w) => Some(Variable::from(w.as_ref())),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                    TextPart::None => vec![],
                })
                .unwrap_or_default()
                .into(),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, variable: &str) -> Variable<'_> {
        Variable::Integer(self.ctx.result.tags.contains(variable).into())
    }
}

pub(crate) struct EmailHeader<'x> {
    pub header: &'x Header<'x>,
    pub raw: &'x str,
}

impl ResolveVariable for EmailHeader<'_> {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        match variable {
            V_HEADER_NAME => self.header.name().into(),
            V_HEADER_NAME_LOWER => CompactString::from_str_to_lowercase(self.header.name()).into(),
            V_HEADER_VALUE | V_HEADER_VALUE_LOWER | V_HEADER_PROPERTY => match &self.header.value {
                HeaderValue::Text(text) => {
                    if variable == V_HEADER_VALUE_LOWER {
                        CompactString::from_str_to_lowercase(text).into()
                    } else {
                        text.as_ref().into()
                    }
                }
                HeaderValue::TextList(list) => Variable::Array(
                    list.iter()
                        .map(|text| {
                            Variable::String(if variable == V_HEADER_VALUE_LOWER {
                                StringCow::Owned(CompactString::from_str_to_lowercase(text))
                            } else {
                                StringCow::Borrowed(text.as_ref())
                            })
                        })
                        .collect(),
                ),
                HeaderValue::Address(address) => Variable::Array(if variable == 1 {
                    address
                        .iter()
                        .filter_map(|a| {
                            a.address.as_ref().map(|text| {
                                Variable::String(if variable == V_HEADER_VALUE_LOWER {
                                    StringCow::Owned(CompactString::from_str_to_lowercase(text))
                                } else {
                                    StringCow::Borrowed(text.as_ref())
                                })
                            })
                        })
                        .collect()
                } else {
                    address
                        .iter()
                        .filter_map(|a| {
                            a.name.as_ref().map(|text| {
                                Variable::String(if variable == V_HEADER_VALUE_LOWER {
                                    StringCow::Owned(CompactString::from_str_to_lowercase(text))
                                } else {
                                    StringCow::Borrowed(text.as_ref())
                                })
                            })
                        })
                        .collect()
                }),
                HeaderValue::DateTime(date_time) => {
                    CompactString::new(date_time.to_rfc3339()).into()
                }
                HeaderValue::ContentType(ct) => {
                    if variable != V_HEADER_PROPERTY {
                        if let Some(st) = ct.subtype() {
                            format_compact!("{}/{}", ct.ctype(), st).into()
                        } else {
                            ct.ctype().into()
                        }
                    } else {
                        Variable::Array(
                            ct.attributes()
                                .map(|attr| {
                                    attr.iter()
                                        .map(|attr| {
                                            Variable::from(format_compact!(
                                                "{}={}", attr.name, attr.value
                                            ))
                                        })
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default(),
                        )
                    }
                }
                HeaderValue::Received(_) => {
                    if variable == V_HEADER_VALUE_LOWER {
                        CompactString::from_str_to_lowercase(self.raw.trim()).into()
                    } else {
                        self.raw.trim().into()
                    }
                }
                HeaderValue::Empty => "".into(),
            },
            V_HEADER_RAW => self.raw.into(),
            V_HEADER_RAW_LOWER => CompactString::from_str_to_lowercase(self.raw).into(),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

impl ResolveVariable for Recipient {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        match variable {
            V_RCPT_EMAIL => Variable::from(self.email.address.as_str()),
            V_RCPT_NAME => Variable::from(self.name.as_deref().unwrap_or_default()),
            V_RCPT_LOCAL => Variable::from(self.email.local_part.as_str()),
            V_RCPT_DOMAIN => Variable::from(self.email.domain_part.fqdn.as_str()),
            V_RCPT_DOMAIN_SLD => Variable::from(self.email.domain_part.sld_or_default()),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

impl ResolveVariable for UrlParts<'_> {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        match variable {
            V_URL_FULL => Variable::from(self.url.as_str()),
            V_URL_PATH_QUERY => Variable::from(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.path_and_query().map(|p| p.as_str()))
                    .unwrap_or_default(),
            ),
            V_URL_PATH => Variable::from(
                self.url_parsed
                    .as_ref()
                    .map(|p| p.parts.path())
                    .unwrap_or_default(),
            ),
            V_URL_QUERY => Variable::from(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.query())
                    .unwrap_or_default(),
            ),
            V_URL_SCHEME => Variable::from(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.scheme_str())
                    .unwrap_or_default(),
            ),
            V_URL_AUTHORITY => Variable::from(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.authority().map(|a| a.as_str()))
                    .unwrap_or_default(),
            ),
            V_URL_HOST => Variable::from(
                self.url_parsed
                    .as_ref()
                    .map(|p| p.host.fqdn.as_str())
                    .unwrap_or_default(),
            ),
            V_URL_HOST_SLD => Variable::from(
                self.url_parsed
                    .as_ref()
                    .map(|p| p.host.sld_or_default())
                    .unwrap_or_default(),
            ),
            V_URL_PORT => Variable::Integer(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.port_u16())
                    .unwrap_or(0) as _,
            ),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

pub struct StringResolver<'x>(pub &'x str);

impl ResolveVariable for StringResolver<'_> {
    fn resolve_variable(&self, _: u32) -> Variable<'_> {
        Variable::from(self.0)
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

pub struct StringListResolver<'x>(pub &'x [String]);

impl ResolveVariable for StringListResolver<'_> {
    fn resolve_variable(&self, _: u32) -> Variable<'_> {
        Variable::Array(self.0.iter().map(|v| Variable::from(v.as_str())).collect())
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}
