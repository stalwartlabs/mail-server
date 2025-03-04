/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod index;

use jmap_proto::types::value::AclGrant;
use utils::BlobHash;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct FileNode {
    pub parent_id: u32,
    pub name: String,
    pub display_name: Option<String>,
    pub file: Option<FileProperties>,
    pub created: u64,
    pub modified: u64,
    pub acls: Vec<AclGrant>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct FileProperties {
    pub blob_hash: BlobHash,
    pub size: u32,
    pub media_type: Option<String>,
    pub executable: bool,
}
