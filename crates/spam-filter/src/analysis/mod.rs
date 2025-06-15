/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
};

use common::{Server, config::spamfilter::Location};
use compact_str::CompactString;
use mail_parser::{Header, parsers::MessageStream};

use crate::{
    Recipient, SpamFilterContext, SpamFilterInput, SpamFilterOutput, SpamFilterResult, TextPart,
};

pub mod bayes;
pub mod date;
pub mod dmarc;
pub mod domain;
pub mod ehlo;
pub mod from;
pub mod headers;
pub mod html;
pub mod init;
pub mod ip;
#[cfg(feature = "enterprise")]
pub mod llm;
pub mod messageid;
pub mod mime;
pub mod pyzor;
pub mod received;
pub mod recipient;
pub mod replyto;
pub mod reputation;
pub mod rules;
pub mod score;
pub mod subject;
pub mod trusted_reply;
pub mod url;

impl SpamFilterInput<'_> {
    pub fn header_as_address(&self, header: &Header<'_>) -> Option<Cow<'_, str>> {
        self.message
            .raw_message()
            .get(header.offset_start as usize..header.offset_end as usize)
            .map(|bytes| MessageStream::new(bytes).parse_address())
            .and_then(|addr| addr.into_address())
            .and_then(|addr| addr.into_list().into_iter().next())
            .and_then(|addr| addr.address)
    }
}

impl SpamFilterOutput<'_> {
    pub fn all_recipients(&self) -> impl Iterator<Item = &Recipient> {
        self.recipients_to
            .iter()
            .chain(self.recipients_cc.iter())
            .chain(self.recipients_bcc.iter())
    }
}

impl SpamFilterContext<'_> {
    pub fn text_body(&self) -> Option<&str> {
        self.input
            .message
            .text_body
            .first()
            .or_else(|| self.input.message.html_body.first())
            .and_then(|idx| self.output.text_parts.get(*idx as usize))
            .and_then(|part| match part {
                TextPart::Plain { text_body, .. } => Some(*text_body),
                TextPart::Html { text_body, .. } => Some(text_body.as_str()),
                TextPart::None => None,
            })
    }
}

impl SpamFilterResult {
    pub fn add_tag(&mut self, tag: impl Into<CompactString>) {
        self.tags.insert(tag.into());
    }

    pub fn has_tag(&self, tag: impl AsRef<str>) -> bool {
        self.tags.contains(tag.as_ref())
    }
}

#[derive(Debug)]
pub struct ElementLocation<T> {
    pub element: T,
    pub location: Location,
}

impl<T: Hash> Hash for ElementLocation<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.element.hash(state);
    }
}

impl<T: PartialEq> PartialEq for ElementLocation<T> {
    fn eq(&self, other: &Self) -> bool {
        self.element.eq(&other.element)
    }
}

impl<T: Eq> Eq for ElementLocation<T> {}

impl<T> ElementLocation<T> {
    pub fn new(element: T, location: impl Into<Location>) -> Self {
        Self {
            element,
            location: location.into(),
        }
    }
}

pub(crate) async fn is_trusted_domain(server: &Server, domain: &str, span_id: u64) -> bool {
    if let Some(store) = server.core.storage.lookups.get("trusted-domains") {
        match store.key_exists(domain).await {
            Ok(true) => return true,
            Ok(false) => (),
            Err(err) => {
                trc::error!(err.span_id(span_id).caused_by(trc::location!()));
            }
        }
    }

    match server.core.storage.directory.is_local_domain(domain).await {
        Ok(result) => result,
        Err(err) => {
            trc::error!(err.span_id(span_id).caused_by(trc::location!()));
            false
        }
    }
}

pub(crate) async fn is_url_redirector(server: &Server, url: &str, span_id: u64) -> bool {
    if let Some(store) = server.core.storage.lookups.get("url-redirectors") {
        match store.key_exists(url).await {
            Ok(result) => result,
            Err(err) => {
                trc::error!(err.span_id(span_id).caused_by(trc::location!()));
                false
            }
        }
    } else {
        false
    }
}
