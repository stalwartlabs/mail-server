/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod hierarchy;
pub mod index;

use dav_proto::schema::request::DeadProperty;
use jmap_proto::types::value::AclGrant;
use store::{SERIALIZE_OBJ_11_V1, SerializedVersion};
use utils::BlobHash;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct FileNode {
    pub parent_id: u32,
    pub name: String,
    pub display_name: Option<String>,
    pub file: Option<FileProperties>,
    pub created: i64,
    pub modified: i64,
    pub dead_properties: DeadProperty,
    pub acls: Vec<AclGrant>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct FileProperties {
    pub blob_hash: BlobHash,
    pub size: u32,
    pub media_type: Option<String>,
    pub executable: bool,
}

impl SerializedVersion for FileNode {
    fn serialize_version() -> u8 {
        SERIALIZE_OBJ_11_V1
    }
}
