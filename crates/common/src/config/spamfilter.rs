/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::SocketAddr, time::Duration};

use ahash::AHashSet;
use hyper::HeaderMap;
use mail_parser::HeaderName;
use utils::{
    config::Config,
    glob::{GlobMap, GlobSet},
};

use super::if_block::IfBlock;

#[derive(Debug, Clone, Default)]
pub struct SpamFilterConfig {
    pub max_rbl_ip_checks: usize,
    pub max_rbl_domain_checks: usize,
    pub max_rbl_email_checks: usize,
    pub max_rbl_url_checks: usize,

    pub greylist_duration: Option<Duration>,

    pub pyzor: Option<PyzorConfig>,
    pub asn: AsnLookupProvider,

    pub list_dmarc_allow: GlobSet,
    pub list_spf_dkim_allow: GlobSet,
    pub list_freemail_providers: GlobSet,
    pub list_disposable_providers: GlobSet,
    pub list_trusted_domains: GlobSet,
    pub list_url_redirectors: GlobSet,
    pub list_file_extensions: GlobMap<FileExtension>,

    pub remote_lists: Vec<RemoteListConfig>,
    pub dnsbls: Vec<DnsblConfig>,
}

#[derive(Debug, Clone, Default)]
pub enum AsnLookupProvider {
    Dns {
        ipv4_zone: String,
        ipv6_zone: String,
        separator: char,
        asn_index: usize,
        country_index: Option<usize>,
    },
    Rest {
        api: String,
        timeout: Duration,
        headers: HeaderMap,
        asn_path: Vec<String>,
        country_path: Option<Vec<String>>,
    },
    #[default]
    None,
}

#[derive(Debug, Clone)]
pub struct PyzorConfig {
    pub address: SocketAddr,
    pub timeout: Duration,
    pub min_count: u64,
    pub min_wl_count: u64,
    pub ratio: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileExtension {
    pub known_types: AHashSet<String>,
    pub is_bad: bool,
    pub is_archive: bool,
    pub is_nz: bool,
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
