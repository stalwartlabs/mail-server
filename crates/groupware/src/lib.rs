/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::types::collection::Collection;
use store::{Deserialize, SerializeInfallible, write::key::KeySerializer};
use utils::codec::leb128::Leb128Reader;

pub mod calendar;
pub mod contact;
pub mod file;
pub mod hierarchy;

pub const IDX_NAME: u8 = 0;
pub const IDX_CARD_UID: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavResourceName {
    Card,
    Cal,
    File,
    Principal,
}

pub struct DestroyArchive<T>(pub T);

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct DavName {
    pub name: String,
    pub parent_id: u32,
}

impl SerializeInfallible for DavName {
    fn serialize(&self) -> Vec<u8> {
        KeySerializer::new(self.name.len() + std::mem::size_of::<u32>())
            .write_leb128(self.parent_id)
            .write(self.name.as_bytes())
            .finalize()
    }
}

impl SerializeInfallible for ArchivedDavName {
    fn serialize(&self) -> Vec<u8> {
        KeySerializer::new(self.name.len() + std::mem::size_of::<u32>())
            .write_leb128(self.parent_id.to_native())
            .write(self.name.as_bytes())
            .finalize()
    }
}

impl DavName {
    pub fn new(name: String, parent_id: u32) -> Self {
        Self { name, parent_id }
    }
}

impl Deserialize for DavName {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let (parent_id, bytes_read) = bytes.read_leb128::<u32>().ok_or_else(|| {
            trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })?;

        let name = bytes
            .get(bytes_read..)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .caused_by(trc::location!())
                    .ctx(trc::Key::Value, bytes)
            })?
            .into();

        Ok(DavName { name, parent_id })
    }
}

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
