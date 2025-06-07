/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::common::timezone::Tz;
use common::DavResources;
use jmap_proto::types::collection::Collection;
use percent_encoding::{AsciiSet, CONTROLS};

pub mod cache;
pub mod calendar;
pub mod contact;
pub mod file;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavResourceName {
    Card,
    Cal,
    File,
    Principal,
}

pub const RFC_3986: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub struct DestroyArchive<T>(pub T);

impl DavResourceName {
    pub fn parse(service: &str) -> Option<Self> {
        hashify::tiny_map!(service.as_bytes(),
            "card" => DavResourceName::Card,
            "cal" => DavResourceName::Cal,
            "file" => DavResourceName::File,
            "pal" => DavResourceName::Principal,
        )
    }

    pub fn base_path(&self) -> &'static str {
        match self {
            DavResourceName::Card => "/dav/card",
            DavResourceName::Cal => "/dav/cal",
            DavResourceName::File => "/dav/file",
            DavResourceName::Principal => "/dav/pal",
        }
    }

    pub fn collection_path(&self) -> &'static str {
        match self {
            DavResourceName::Card => "/dav/card/",
            DavResourceName::Cal => "/dav/cal/",
            DavResourceName::File => "/dav/file/",
            DavResourceName::Principal => "/dav/pal/",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            DavResourceName::Card => "CardDAV",
            DavResourceName::Cal => "CalDAV",
            DavResourceName::File => "WebDAV",
            DavResourceName::Principal => "Principal",
        }
    }
}

impl From<DavResourceName> for Collection {
    fn from(value: DavResourceName) -> Self {
        match value {
            DavResourceName::Card => Collection::AddressBook,
            DavResourceName::Cal => Collection::Calendar,
            DavResourceName::File => Collection::FileNode,
            DavResourceName::Principal => Collection::Principal,
        }
    }
}

impl From<Collection> for DavResourceName {
    fn from(value: Collection) -> Self {
        match value {
            Collection::AddressBook => DavResourceName::Card,
            Collection::Calendar => DavResourceName::Cal,
            Collection::FileNode => DavResourceName::File,
            Collection::Principal => DavResourceName::Principal,
            _ => unreachable!(),
        }
    }
}

pub trait DavCalendarResource {
    fn calendar_default_tz(&self, calendar_id: u32) -> Option<Tz>;
}

impl DavCalendarResource for DavResources {
    fn calendar_default_tz(&self, calendar_id: u32) -> Option<Tz> {
        self.container_resource_by_id(calendar_id)
            .and_then(|c| c.timezone())
    }
}
