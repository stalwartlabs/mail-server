/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use ahash::AHashSet;
use mail_parser::HeaderName;
use utils::{config::Config, glob::GlobSet};

use super::if_block::IfBlock;

#[derive(Debug, Clone, Default)]
pub struct SpamFilterConfig {
    pub max_rbl_ip_checks: usize,
    pub max_rbl_domain_checks: usize,
    pub max_rbl_email_checks: usize,
    pub max_rbl_url_checks: usize,

    pub list_dmarc_allow: GlobSet,
    pub list_spf_dkim_allow: GlobSet,
    pub list_freemail_providers: GlobSet,
    pub list_disposable_providers: GlobSet,
    pub list_trusted_domains: GlobSet,
    pub list_url_redirectors: GlobSet,
    pub remote_lists: Vec<RemoteListConfig>,
    pub dnsbls: Vec<DnsblConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Element {
    Url,
    Domain,
    Email,
    Ip,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Location {
    EnvelopeFrom,
    EnvelopeTo,
    DkimPassing,
    Ehlo,
    Header(HeaderName<'static>),
    BodyText,
    BodyHtml,
    BodyRaw,
    Message,
    Attachment,
    Tcp,
}

#[derive(Debug, Clone)]
pub struct RemoteListConfig {
    pub id: String,
    pub url: String,
    pub retry: Duration,       // 1 hour
    pub refresh: Duration,     // 12h openphish, 6h phishtank
    pub timeout: Duration,     // 10s
    pub max_size: usize,       // 10MB
    pub max_entries: usize,    // 100000
    pub max_entry_size: usize, // 256
    pub format: RemoteListFormat,
    pub element: Element,
    pub element_location: AHashSet<Location>,
    pub tag: String,
}

#[derive(Debug, Clone)]
pub struct DnsblConfig {
    pub id: String,
    pub zone: IfBlock,
    pub element: Element,
    pub element_location: AHashSet<Location>,
    pub tags: IfBlock,
}

#[derive(Debug, Clone)]
pub enum RemoteListFormat {
    List,
    Csv {
        column: u32,
        separator: char,
        skip_first: bool,
    },
}

impl SpamFilterConfig {
    pub fn parse(config: &mut Config) -> Self {
        SpamFilterConfig::default()
    }
}

impl From<HeaderName<'static>> for Location {
    fn from(header: HeaderName<'static>) -> Self {
        Location::Header(header)
    }
}
