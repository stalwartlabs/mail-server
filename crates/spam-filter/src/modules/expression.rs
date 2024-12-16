/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use std::net::IpAddr;

use common::{
    config::spamfilter::Location,
    expr::{functions::ResolveVariable, tokenizer::TokenMap, Variable},
};
use mail_auth::common::resolver::ToReverseName;
use mail_parser::{Header, HeaderValue};

use crate::{analysis::url::UrlParts, Recipient, SpamFilterContext, TextPart};

pub const V_SPAM_REMOTE_IP: u32 = 100;
pub const V_SPAM_REMOTE_IP_PTR: u32 = 101;
pub const V_SPAM_EHLO_DOMAIN: u32 = 102;
pub const V_SPAM_AUTH_AS: u32 = 103;
pub const V_SPAM_ASN: u32 = 104;
pub const V_SPAM_COUNTRY: u32 = 105;
pub const V_SPAM_TLS_VERSION: u32 = 106;
pub const V_SPAM_TLS_CIPHER: u32 = 107;
pub const V_SPAM_ENV_FROM: u32 = 108;
pub const V_SPAM_ENV_FROM_LOCAL: u32 = 109;
pub const V_SPAM_ENV_FROM_DOMAIN: u32 = 110;
pub const V_SPAM_ENV_TO: u32 = 111;
pub const V_SPAM_FROM: u32 = 112;
pub const V_SPAM_FROM_NAME: u32 = 113;
pub const V_SPAM_FROM_LOCAL: u32 = 114;
pub const V_SPAM_FROM_DOMAIN: u32 = 115;
pub const V_SPAM_REPLY_TO: u32 = 116;
pub const V_SPAM_REPLY_TO_NAME: u32 = 117;
pub const V_SPAM_REPLY_TO_LOCAL: u32 = 118;
pub const V_SPAM_REPLY_TO_DOMAIN: u32 = 119;
pub const V_SPAM_TO: u32 = 120;
pub const V_SPAM_TO_NAME: u32 = 121;
pub const V_SPAM_TO_LOCAL: u32 = 122;
pub const V_SPAM_TO_DOMAIN: u32 = 123;
pub const V_SPAM_CC: u32 = 124;
pub const V_SPAM_CC_NAME: u32 = 125;
pub const V_SPAM_CC_LOCAL: u32 = 126;
pub const V_SPAM_CC_DOMAIN: u32 = 127;
pub const V_SPAM_BCC: u32 = 128;
pub const V_SPAM_BCC_NAME: u32 = 129;
pub const V_SPAM_BCC_LOCAL: u32 = 130;
pub const V_SPAM_BCC_DOMAIN: u32 = 131;
pub const V_SPAM_BODY_TEXT: u32 = 132;
pub const V_SPAM_BODY_HTML: u32 = 133;
pub const V_SPAM_BODY_RAW: u32 = 134;
pub const V_SPAM_SUBJECT: u32 = 135;
pub const V_SPAM_SUBJECT_THREAD: u32 = 136;
pub const V_SPAM_LOCATION: u32 = 137;

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
            V_SPAM_REMOTE_IP => self.ctx.input.remote_ip.to_string().into(),
            V_SPAM_REMOTE_IP_PTR => self
                .ctx
                .output
                .iprev_ptr
                .as_deref()
                .unwrap_or_default()
                .into(),
            V_SPAM_EHLO_DOMAIN => self.ctx.output.ehlo_host.fqdn.as_str().into(),
            V_SPAM_AUTH_AS => self.ctx.input.authenticated_as.into(),
            V_SPAM_ASN => self.ctx.input.asn.unwrap_or_default().into(),
            V_SPAM_COUNTRY => self.ctx.input.country.unwrap_or_default().into(),
            V_SPAM_TLS_VERSION => self.ctx.input.tls_version.into(),
            V_SPAM_TLS_CIPHER => self.ctx.input.tls_cipher.into(),
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
                .map(|e| Variable::String(e.address.as_str().into()))
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
                .map(|r| Variable::String(r.email.address.as_str().into()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_TO_NAME => self
                .ctx
                .output
                .recipients_to
                .iter()
                .filter_map(|r| Variable::String(r.name.as_deref()?.into()).into())
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_TO_LOCAL => self
                .ctx
                .output
                .recipients_to
                .iter()
                .map(|r| Variable::String(r.email.local_part.as_str().into()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_TO_DOMAIN => self
                .ctx
                .output
                .recipients_to
                .iter()
                .map(|r| Variable::String(r.email.domain_part.fqdn.as_str().into()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_CC => self
                .ctx
                .output
                .recipients_cc
                .iter()
                .map(|r| Variable::String(r.email.address.as_str().into()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_CC_NAME => self
                .ctx
                .output
                .recipients_cc
                .iter()
                .filter_map(|r| Variable::String(r.name.as_deref()?.into()).into())
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_CC_LOCAL => self
                .ctx
                .output
                .recipients_cc
                .iter()
                .map(|r| Variable::String(r.email.local_part.as_str().into()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_CC_DOMAIN => self
                .ctx
                .output
                .recipients_cc
                .iter()
                .map(|r| Variable::String(r.email.domain_part.fqdn.as_str().into()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_BCC => self
                .ctx
                .output
                .recipients_bcc
                .iter()
                .map(|r| Variable::String(r.email.address.as_str().into()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_BCC_NAME => self
                .ctx
                .output
                .recipients_bcc
                .iter()
                .filter_map(|r| Variable::String(r.name.as_deref()?.into()).into())
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_BCC_LOCAL => self
                .ctx
                .output
                .recipients_bcc
                .iter()
                .map(|r| Variable::String(r.email.local_part.as_str().into()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_BCC_DOMAIN => self
                .ctx
                .output
                .recipients_bcc
                .iter()
                .map(|r| Variable::String(r.email.domain_part.fqdn.as_str().into()))
                .collect::<Vec<_>>()
                .into(),
            V_SPAM_BODY_TEXT => self
                .ctx
                .input
                .message
                .text_body
                .first()
                .or_else(|| self.ctx.input.message.html_body.first())
                .and_then(|idx| self.ctx.output.text_parts.get(*idx))
                .map(|part| {
                    match part {
                        TextPart::Plain { text_body, .. } => text_body,
                        TextPart::Html { text_body, .. } => text_body.as_str(),
                        TextPart::None => "",
                    }
                    .into()
                })
                .unwrap_or_default(),
            V_SPAM_BODY_HTML => self
                .ctx
                .input
                .message
                .html_body
                .first()
                .and_then(|idx| self.ctx.output.text_parts.get(*idx))
                .map(|part| {
                    if let TextPart::Html { text_body, .. } = part {
                        text_body.as_str().into()
                    } else {
                        "".into()
                    }
                })
                .unwrap_or_default(),
            V_SPAM_BODY_RAW => Variable::String(String::from_utf8_lossy(
                self.ctx.input.message.raw_message(),
            )),
            V_SPAM_SUBJECT => self.ctx.output.subject.as_str().into(),
            V_SPAM_SUBJECT_THREAD => self.ctx.output.subject_thread.as_str().into(),
            V_SPAM_LOCATION => self.location.as_str().into(),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, variable: &str) -> Variable<'_> {
        Variable::Integer(self.ctx.result.tags.contains(variable).into())
    }
}

pub fn spam_token_map() -> TokenMap {
    TokenMap::default().with_variables_map([
        ("remote_ip", V_SPAM_REMOTE_IP),
        ("remote_ip.ptr", V_SPAM_REMOTE_IP_PTR),
        ("ehlo_domain", V_SPAM_EHLO_DOMAIN),
        ("auth_as", V_SPAM_AUTH_AS),
        ("asn", V_SPAM_ASN),
        ("country", V_SPAM_COUNTRY),
        ("tls_version", V_SPAM_TLS_VERSION),
        ("tls_cipher", V_SPAM_TLS_CIPHER),
        ("env_from", V_SPAM_ENV_FROM),
        ("env_from.local", V_SPAM_ENV_FROM_LOCAL),
        ("env_from.domain", V_SPAM_ENV_FROM_DOMAIN),
        ("env_to", V_SPAM_ENV_TO),
        ("from", V_SPAM_FROM),
        ("from.name", V_SPAM_FROM_NAME),
        ("from.local", V_SPAM_FROM_LOCAL),
        ("from.domain", V_SPAM_FROM_DOMAIN),
        ("reply_to", V_SPAM_REPLY_TO),
        ("reply_to.name", V_SPAM_REPLY_TO_NAME),
        ("reply_to.local", V_SPAM_REPLY_TO_LOCAL),
        ("reply_to.domain", V_SPAM_REPLY_TO_DOMAIN),
        ("to", V_SPAM_TO),
        ("to.name", V_SPAM_TO_NAME),
        ("to.local", V_SPAM_TO_LOCAL),
        ("to.domain", V_SPAM_TO_DOMAIN),
        ("cc", V_SPAM_CC),
        ("cc.name", V_SPAM_CC_NAME),
        ("cc.local", V_SPAM_CC_LOCAL),
        ("cc.domain", V_SPAM_CC_DOMAIN),
        ("bcc", V_SPAM_BCC),
        ("bcc.name", V_SPAM_BCC_NAME),
        ("bcc.local", V_SPAM_BCC_LOCAL),
        ("bcc.domain", V_SPAM_BCC_DOMAIN),
        ("body", V_SPAM_BODY_TEXT),
        ("body.text", V_SPAM_BODY_TEXT),
        ("body.html", V_SPAM_BODY_HTML),
        ("body.raw", V_SPAM_BODY_RAW),
        ("subject", V_SPAM_SUBJECT),
        ("subject.thread", V_SPAM_SUBJECT_THREAD),
        ("location", V_SPAM_LOCATION),
    ])
}

pub(crate) struct EmailHeader<'x> {
    pub header: &'x Header<'x>,
    pub raw: &'x str,
}

pub fn mail_header_token_map() -> TokenMap {
    TokenMap::default().with_variables_map([
        ("name", 0),
        ("value", 1),
        ("email", 1),
        ("name", 2),
        ("attributes", 2),
        ("raw", 3),
    ])
}

impl ResolveVariable for EmailHeader<'_> {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        match variable {
            0 => self.header.name().into(),
            1 | 2 => match &self.header.value {
                HeaderValue::Text(text) => text.as_ref().into(),
                HeaderValue::TextList(list) => Variable::Array(
                    list.iter()
                        .map(|v| Variable::String(v.as_ref().into()))
                        .collect(),
                ),
                HeaderValue::Address(address) => Variable::Array(if variable == 1 {
                    address
                        .iter()
                        .filter_map(|a| {
                            a.address
                                .as_ref()
                                .map(|a| Variable::String(a.as_ref().into()))
                        })
                        .collect()
                } else {
                    address
                        .iter()
                        .filter_map(|a| {
                            a.name.as_ref().map(|a| Variable::String(a.as_ref().into()))
                        })
                        .collect()
                }),
                HeaderValue::DateTime(date_time) => date_time.to_rfc3339().into(),
                HeaderValue::ContentType(ct) => {
                    if variable == 1 {
                        if let Some(st) = ct.subtype() {
                            format!("{}/{}", ct.ctype(), st).into()
                        } else {
                            ct.ctype().into()
                        }
                    } else {
                        Variable::Array(
                            ct.attributes()
                                .map(|attr| {
                                    attr.iter()
                                        .map(|(k, v)| Variable::String(format!("{k}={v}").into()))
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default(),
                        )
                    }
                }
                HeaderValue::Received(_) => self.raw.trim().into(),
                HeaderValue::Empty => "".into(),
            },
            3 => self.raw.into(),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

pub const V_RCPT_EMAIL: u32 = 0;
pub const V_RCPT_NAME: u32 = 1;
pub const V_RCPT_LOCAL: u32 = 2;
pub const V_RCPT_DOMAIN: u32 = 3;
pub const V_RCPT_DOMAIN_SLD: u32 = 4;

impl ResolveVariable for Recipient {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        match variable {
            V_RCPT_EMAIL => Variable::String(self.email.address.as_str().into()),
            V_RCPT_NAME => Variable::String(self.name.as_deref().unwrap_or_default().into()),
            V_RCPT_LOCAL => Variable::String(self.email.local_part.as_str().into()),
            V_RCPT_DOMAIN => Variable::String(self.email.domain_part.fqdn.as_str().into()),
            V_RCPT_DOMAIN_SLD => Variable::String(self.email.domain_part.sld_or_default().into()),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

impl Recipient {
    pub fn token_map() -> TokenMap {
        TokenMap::default().with_variables_map([
            ("email", V_RCPT_EMAIL),
            ("name", V_RCPT_NAME),
            ("local", V_RCPT_LOCAL),
            ("domain", V_RCPT_DOMAIN),
            ("sld", V_RCPT_DOMAIN_SLD),
        ])
    }
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

impl ResolveVariable for UrlParts {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        match variable {
            V_URL_FULL => Variable::String(self.url.as_str().into()),
            V_URL_PATH_QUERY => Variable::String(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.path_and_query().map(|p| p.as_str()))
                    .unwrap_or_default()
                    .into(),
            ),
            V_URL_PATH => Variable::String(
                self.url_parsed
                    .as_ref()
                    .map(|p| p.parts.path())
                    .unwrap_or_default()
                    .into(),
            ),
            V_URL_QUERY => Variable::String(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.query())
                    .unwrap_or_default()
                    .into(),
            ),
            V_URL_SCHEME => Variable::String(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.scheme_str())
                    .unwrap_or_default()
                    .into(),
            ),
            V_URL_AUTHORITY => Variable::String(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.authority().map(|a| a.as_str()))
                    .unwrap_or_default()
                    .into(),
            ),
            V_URL_HOST => Variable::String(
                self.url_parsed
                    .as_ref()
                    .map(|p| p.host.fqdn.as_str())
                    .unwrap_or_default()
                    .into(),
            ),
            V_URL_HOST_SLD => Variable::String(
                self.url_parsed
                    .as_ref()
                    .map(|p| p.host.sld_or_default())
                    .unwrap_or_default()
                    .into(),
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

impl UrlParts {
    pub fn token_map() -> TokenMap {
        TokenMap::default().with_variables_map([
            ("url", V_URL_FULL),
            ("path_query", V_URL_PATH_QUERY),
            ("path", V_URL_PATH),
            ("query", V_URL_QUERY),
            ("scheme", V_URL_SCHEME),
            ("authority", V_URL_AUTHORITY),
            ("host", V_URL_HOST),
            ("sld", V_URL_HOST_SLD),
            ("port", V_URL_PORT),
        ])
    }
}

pub struct StringResolver<'x>(pub &'x str);

impl ResolveVariable for StringResolver<'_> {
    fn resolve_variable(&self, _: u32) -> Variable<'_> {
        Variable::String(self.0.into())
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

pub struct StringListResolver<'x>(pub &'x [String]);

impl ResolveVariable for StringListResolver<'_> {
    fn resolve_variable(&self, _: u32) -> Variable<'_> {
        Variable::Array(self.0.iter().map(|v| Variable::String(v.into())).collect())
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

pub struct IpResolver(pub IpAddr);

impl ResolveVariable for IpResolver {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        match variable {
            0 => Variable::String(self.0.to_string().into()),
            1 => Variable::String(self.0.to_reverse_name().into()),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

pub fn new_ip() -> TokenMap {
    TokenMap::default().with_variables_map([("ip", 0), ("reverse_ip", 1)])
}
