/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavResourceName, RFC_3986,
    file::{ArchivedFileNode, FileNode},
};
use common::{DavPath, DavResource, DavResourceMetadata, DavResources, Server};
use directory::backend::internal::manage::ManageDirectory;
use jmap_proto::types::{
    collection::{Collection, SyncCollection},
    property::Property,
    value::AclGrant,
};
use std::sync::Arc;
use store::{
    Deserialize, IterateParams, U32_LEN, ValueKey,
    ahash::{AHashMap, AHashSet},
    write::{AlignedBytes, Archive, ValueClass, key::DeserializeBigEndian},
};
use tokio::sync::Semaphore;
use trc::AddContext;
use utils::{map::bitmap::Bitmap, topological::TopologicalSort};

pub(super) async fn build_file_resources(
    server: &Server,
    account_id: u32,
    update_lock: Arc<Semaphore>,
) -> trc::Result<DavResources> {
    let last_change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, SyncCollection::FileNode)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let name = server
        .store()
        .get_principal_name(account_id)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_else(|| format!("_{account_id}"));
    let resources = fetch_files(server, account_id).await?;
    let mut files = DavResources {
        base_path: format!(
            "{}/{}/",
            DavResourceName::File.base_path(),
            percent_encoding::utf8_percent_encode(&name, RFC_3986),
        ),
        size: std::mem::size_of::<DavResources>() as u64,
        paths: AHashSet::with_capacity(resources.len()),
        resources,
        item_change_id: last_change_id,
        container_change_id: last_change_id,
        highest_change_id: last_change_id,
        update_lock,
    };

    build_nested_hierarchy(&mut files);

    Ok(files)
}

pub(super) fn build_nested_hierarchy(resources: &mut DavResources) {
    let mut topological_sort = TopologicalSort::with_capacity(resources.resources.len());
    let mut names = AHashMap::with_capacity(resources.resources.len());

    for (resource_idx, resource) in resources.resources.iter().enumerate() {
        if let DavResourceMetadata::File { parent_id, .. } = resource.data {
            topological_sort.insert(
                parent_id.map(|id| id + 1).unwrap_or_default(),
                resource.document_id + 1,
            );
            names.insert(
                resource.document_id,
                DavPath {
                    path: resource.container_name().unwrap().to_string(),
                    parent_id,
                    hierarchy_seq: 0,
                    resource_idx,
                },
            );
        }
    }

    for (hierarchy_sequence, folder_id) in topological_sort.into_iterator().enumerate() {
        if folder_id != 0 {
            let folder_id = folder_id - 1;
            if let Some((name, parent_name)) = names
                .get(&folder_id)
                .and_then(|folder| folder.parent_id.map(|parent_id| (&folder.path, parent_id)))
                .and_then(|(name, parent_id)| {
                    names.get(&parent_id).map(|folder| (name, &folder.path))
                })
            {
                let name = format!("{parent_name}/{name}");
                let folder = names.get_mut(&folder_id).unwrap();
                folder.path = name;
                folder.hierarchy_seq = hierarchy_sequence as u32;
            } else {
                names.get_mut(&folder_id).unwrap().hierarchy_seq = hierarchy_sequence as u32;
            }
        }
    }

    resources.paths = names
        .into_values()
        .inspect(|v| {
            resources.size += (std::mem::size_of::<DavPath>()
                + std::mem::size_of::<u32>()
                + std::mem::size_of::<usize>()
                + std::mem::size_of::<DavResource>()
                + v.path.len()) as u64;
        })
        .collect();
}

async fn fetch_files(server: &Server, account_id: u32) -> trc::Result<Vec<DavResource>> {
    let mut files = Vec::with_capacity(16);

    server
        .store()
        .iterate(
            IterateParams::new(
                ValueKey {
                    account_id,
                    collection: Collection::FileNode.into(),
                    document_id: 0,
                    class: ValueClass::Property(Property::Value.into()),
                },
                ValueKey {
                    account_id,
                    collection: Collection::FileNode.into(),
                    document_id: u32::MAX,
                    class: ValueClass::Property(Property::Value.into()),
                },
            ),
            |key, value| {
                let archive = <Archive<AlignedBytes> as Deserialize>::deserialize(value)?;

                files.push(resource_from_file(
                    archive.unarchive::<FileNode>()?,
                    key.deserialize_be_u32(key.len() - U32_LEN)?,
                ));

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    Ok(files)
}

pub(super) fn resource_from_file(node: &ArchivedFileNode, document_id: u32) -> DavResource {
    let parent_id = node.parent_id.to_native();
    DavResource {
        document_id,
        data: DavResourceMetadata::File {
            name: node.name.as_str().to_string(),
            size: node.file.as_ref().map(|f| f.size.to_native()),
            parent_id: if parent_id > 0 {
                Some(parent_id - 1)
            } else {
                None
            },
            acls: node
                .acls
                .iter()
                .map(|acl| AclGrant {
                    account_id: acl.account_id.to_native(),
                    grants: Bitmap::from(&acl.grants),
                })
                .collect(),
        },
    }
}
