/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{DavResource, DavResourceId, DavResources, Server, auth::AccessToken};
use directory::backend::internal::manage::ManageDirectory;
use jmap_proto::types::collection::Collection;
use percent_encoding::NON_ALPHANUMERIC;
use store::{
    Deserialize, IndexKey, IndexKeyPrefix, IterateParams, SerializeInfallible, U32_LEN,
    ahash::AHashMap,
    write::{BatchBuilder, key::DeserializeBigEndian},
};
use trc::AddContext;
use utils::bimap::IdBimap;

use crate::{DavName, DavResourceName, IDX_NAME, contact::AddressBook, file::FileNode};

pub trait DavHierarchy: Sync + Send {
    fn fetch_dav_resources(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
    ) -> impl Future<Output = trc::Result<Arc<DavResources>>> + Send;

    fn create_default_addressbook(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn create_default_calendar(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl DavHierarchy for Server {
    async fn fetch_dav_resources(
        &self,
        access_token: &AccessToken,
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
                    let files = build_hierarchy(self, account_id, collection).await?;
                    if files.paths.is_empty() {
                        match collection {
                            Collection::Calendar => {
                                self.create_default_calendar(access_token, account_id)
                                    .await?
                            }
                            Collection::AddressBook => {
                                self.create_default_addressbook(access_token, account_id)
                                    .await?
                            }
                            _ => unreachable!(),
                        }
                        build_hierarchy(self, account_id, collection).await?
                    } else {
                        files
                    }
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

    async fn create_default_addressbook(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<()> {
        if let Some(name) = &self.core.dav.default_addressbook_name {
            let mut batch = BatchBuilder::new();
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::AddressBook, 1)
                .await?;
            AddressBook {
                name: name.clone(),
                display_name: self.core.dav.default_addressbook_display_name.clone(),
                is_default: true,
                ..Default::default()
            }
            .insert(access_token, account_id, document_id, &mut batch)?;
            self.commit_batch(batch).await?;
        }

        Ok(())
    }

    async fn create_default_calendar(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<()> {
        todo!()
    }
}

async fn build_hierarchy(
    server: &Server,
    account_id: u32,
    collection: Collection,
) -> trc::Result<DavResources> {
    let base_path = DavResourceName::from(collection).base_path();
    let collection = u8::from(collection);
    let mut containers: AHashMap<u32, String> = AHashMap::with_capacity(16);
    let mut resources: AHashMap<u32, Vec<DavName>> = AHashMap::with_capacity(16);

    server
        .store()
        .iterate(
            IterateParams::new(
                IndexKey {
                    account_id,
                    collection,
                    document_id: 0,
                    field: IDX_NAME,
                    key: 0u32.serialize(),
                },
                IndexKey {
                    account_id,
                    collection: collection + 1,
                    document_id: u32::MAX,
                    field: IDX_NAME,
                    key: u32::MAX.serialize(),
                },
            )
            .no_values()
            .ascending(),
            |key, _| {
                let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                let value = key
                    .get(IndexKeyPrefix::len()..key.len() - U32_LEN)
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                let key_collection = key
                    .get(U32_LEN)
                    .copied()
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

                if key_collection == collection {
                    containers.insert(
                        document_id,
                        std::str::from_utf8(value)
                            .map_err(|_| trc::Error::corrupted_key(key, None, trc::location!()))?
                            .to_string(),
                    );
                } else {
                    resources.entry(document_id).or_default().push(
                        DavName::deserialize(value)
                            .map_err(|_| trc::Error::corrupted_key(key, None, trc::location!()))?,
                    );
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let name = server
        .store()
        .get_principal_name(account_id)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_else(|| format!("_{account_id}"));

    let mut files = DavResources {
        paths: IdBimap::with_capacity(containers.len() + resources.len()),
        size: std::mem::size_of::<DavResources>() as u64,
        modseq: None,
        base_path: format!(
            "{}/{}/",
            base_path,
            percent_encoding::utf8_percent_encode(&name, NON_ALPHANUMERIC),
        ),
    };

    for (document_id, dav_names) in resources {
        for dav_name in dav_names {
            if let Some(container) = containers.get(&dav_name.parent_id) {
                let name = format!("{}/{}", container, dav_name.name);
                files.size += (std::mem::size_of::<u32>()
                    + std::mem::size_of::<String>()
                    + name.len()) as u64;
                files.paths.insert(DavResource {
                    document_id,
                    parent_id: dav_name.parent_id.into(),
                    name,
                    size: 0,
                    is_container: false,
                    hierarchy_sequence: 1,
                });
            }
        }
    }

    for (document_id, name) in containers {
        files.size +=
            (std::mem::size_of::<u32>() + std::mem::size_of::<String>() + name.len()) as u64;
        files.paths.insert(DavResource {
            document_id,
            parent_id: None,
            name,
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
    let name = server
        .store()
        .get_principal_name(account_id)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_else(|| format!("_{account_id}"));
    let mut files = DavResources {
        base_path: format!(
            "{}/{}/",
            DavResourceName::Card.base_path(),
            percent_encoding::utf8_percent_encode(&name, NON_ALPHANUMERIC),
        ),
        paths: IdBimap::with_capacity(list.len()),
        size: std::mem::size_of::<DavResources>() as u64,
        modseq: None,
    };

    for expanded in list.into_iterator() {
        files.size += (std::mem::size_of::<u32>()
            + std::mem::size_of::<String>()
            + expanded.name.len()) as u64;
        files.paths.insert(DavResource {
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
