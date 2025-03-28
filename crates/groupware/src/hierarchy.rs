/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{DavResource, DavResourceId, DavResources, Server};
use jmap_proto::types::{collection::Collection, property::Property};
use store::{
    Deserialize, IndexKey, IterateParams, SerializeInfallible, U32_LEN, ahash::AHashMap,
    write::key::DeserializeBigEndian,
};
use trc::AddContext;
use utils::bimap::IdBimap;

use crate::file::FileNode;

pub trait DavHierarchy: Sync + Send {
    fn fetch_dav_hierarchy(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> impl Future<Output = trc::Result<Arc<DavResources>>> + Send;
}

impl DavHierarchy for Server {
    async fn fetch_dav_hierarchy(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> trc::Result<Arc<DavResources>> {
        let change_id = self
            .store()
            .get_last_change_id(account_id, collection)
            .await
            .caused_by(trc::location!())?;
        let resource_id = DavResourceId {
            account_id,
            collection: collection.into(),
        };
        if let Some(files) = self
            .inner
            .cache
            .dav
            .get(&resource_id)
            .filter(|x| x.modseq == change_id)
        {
            Ok(files)
        } else {
            let mut files = match collection {
                Collection::Calendar | Collection::AddressBook => {
                    build_hierarchy(self, account_id, collection).await?
                }
                Collection::FileNode => build_file_hierarchy(self, account_id).await?,
                _ => unreachable!(),
            };

            files.modseq = change_id;
            let files = Arc::new(files);
            self.inner.cache.dav.insert(resource_id, files.clone());
            Ok(files)
        }
    }
}

#[derive(Default)]
struct DavTempResource {
    name: String,
    parent_id: Vec<u32>,
}

async fn build_hierarchy(
    server: &Server,
    account_id: u32,
    collection: Collection,
) -> trc::Result<DavResources> {
    let collection = u8::from(collection);
    let mut containers: AHashMap<u32, DavTempResource> = AHashMap::with_capacity(16);
    let mut resources: AHashMap<u32, DavTempResource> = AHashMap::with_capacity(16);

    server
        .store()
        .iterate(
            IterateParams::new(
                IndexKey {
                    account_id,
                    collection,
                    document_id: 0,
                    field: 0,
                    key: 0u32.serialize(),
                },
                IndexKey {
                    account_id,
                    collection: collection + 1,
                    document_id: u32::MAX,
                    field: u8::MAX,
                    key: u32::MAX.serialize(),
                },
            )
            .no_values()
            .ascending(),
            |key, _| {
                let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                let value = key
                    .get(key.len() - (U32_LEN * 2)..key.len() - U32_LEN)
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                let key_collection = key
                    .get(U32_LEN)
                    .copied()
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                let key_property = key
                    .get(U32_LEN + 1)
                    .copied()
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

                let resource = if key_collection == collection {
                    containers.entry(document_id).or_default()
                } else {
                    resources.entry(document_id).or_default()
                };

                if key_property == u8::from(Property::Value) {
                    resource.name = std::str::from_utf8(value)
                        .map_err(|_| trc::Error::corrupted_key(key, None, trc::location!()))?
                        .to_string();
                } else if key_property == u8::from(Property::ParentId) {
                    resource.parent_id.push(
                        u32::deserialize(value)
                            .map_err(|_| trc::Error::corrupted_key(key, None, trc::location!()))?,
                    );
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let mut files = DavResources {
        files: IdBimap::with_capacity(containers.len() + resources.len()),
        size: std::mem::size_of::<DavResources>() as u64,
        modseq: None,
    };

    for (document_id, resource) in resources {
        for parent_id in resource.parent_id {
            if let Some(container) = containers.get(&parent_id) {
                let name = format!("{}/{}", container.name, resource.name);
                files.size += (std::mem::size_of::<u32>()
                    + std::mem::size_of::<String>()
                    + name.len()) as u64;
                files.files.insert(DavResource {
                    document_id,
                    parent_id: parent_id.into(),
                    name,
                    size: 0,
                    is_container: false,
                    hierarchy_sequence: 1,
                });
            }
        }
    }

    for (document_id, container) in containers {
        files.size += (std::mem::size_of::<u32>()
            + std::mem::size_of::<String>()
            + container.name.len()) as u64;
        files.files.insert(DavResource {
            document_id,
            parent_id: None,
            name: container.name,
            size: 0,
            is_container: true,
            hierarchy_sequence: 0,
        });
    }

    Ok(files)
}

async fn build_file_hierarchy(server: &Server, account_id: u32) -> trc::Result<DavResources> {
    let list = server
        .fetch_folders::<FileNode>(account_id, Collection::FileNode)
        .await
        .caused_by(trc::location!())?;
    let mut files = DavResources {
        files: IdBimap::with_capacity(list.len()),
        size: std::mem::size_of::<DavResources>() as u64,
        modseq: None,
    };

    for expanded in list.into_iterator() {
        files.size += (std::mem::size_of::<u32>()
            + std::mem::size_of::<String>()
            + expanded.name.len()) as u64;
        files.files.insert(DavResource {
            document_id: expanded.document_id,
            parent_id: expanded.parent_id,
            name: expanded.name,
            size: expanded.size,
            is_container: expanded.is_container,
            hierarchy_sequence: expanded.hierarchy_sequence,
        });
    }

    Ok(files)
}
