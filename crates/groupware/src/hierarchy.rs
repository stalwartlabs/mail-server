/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavName, DavResourceName, IDX_NAME, IDX_TIME,
    calendar::{Calendar, CalendarPreferences},
    contact::AddressBook,
    file::FileNode,
};
use calcard::common::timezone::Tz;
use common::{
    DavResource, DavResourceId, DavResourceMetadata, DavResources, Server, auth::AccessToken,
};
use directory::backend::internal::manage::ManageDirectory;
use jmap_proto::types::collection::Collection;
use percent_encoding::NON_ALPHANUMERIC;
use std::sync::Arc;
use store::{
    Deserialize, IndexKey, IndexKeyPrefix, IterateParams, SerializeInfallible, U32_LEN, U64_LEN,
    ahash::AHashMap,
    write::{BatchBuilder, key::DeserializeBigEndian},
};
use trc::AddContext;
use utils::bimap::IdBimap;

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

    fn cached_dav_resources(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> Option<Arc<DavResources>>;
}

impl DavHierarchy for Server {
    async fn fetch_dav_resources(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
    ) -> trc::Result<Arc<DavResources>> {
        let todo = "fix";

        let is_files = collection == Collection::FileNode;
        let mut change_id = self
            .store()
            .get_last_change_id(account_id, collection)
            .await
            .caused_by(trc::location!())?;
        if !is_files {
            let child_change_id = self
                .store()
                .get_last_change_id(account_id, collection.child_collection().unwrap())
                .await
                .caused_by(trc::location!())?;
            change_id = change_id.max(child_change_id);
        }

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
            let mut files = if !is_files {
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
            } else {
                build_file_hierarchy(self, account_id).await?
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
        if let Some(name) = &self.core.groupware.default_addressbook_name {
            let mut batch = BatchBuilder::new();
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::AddressBook, 1)
                .await?;
            AddressBook {
                name: name.clone(),
                display_name: self.core.groupware.default_addressbook_display_name.clone(),
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
        if let Some(name) = &self.core.groupware.default_calendar_name {
            let mut batch = BatchBuilder::new();
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::Calendar, 1)
                .await?;
            Calendar {
                name: name.clone(),
                preferences: vec![CalendarPreferences {
                    account_id,
                    name: name.clone(),
                    description: self.core.groupware.default_calendar_display_name.clone(),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .insert(access_token, account_id, document_id, &mut batch)?;
            self.commit_batch(batch).await?;
        }

        Ok(())
    }

    fn cached_dav_resources(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> Option<Arc<DavResources>> {
        self.inner
            .cache
            .dav
            .get(&DavResourceId {
                account_id,
                collection: collection.into(),
            })
            .clone()
    }
}

async fn build_hierarchy(
    server: &Server,
    account_id: u32,
    collection_: Collection,
) -> trc::Result<DavResources> {
    let base_path = DavResourceName::from(collection_).base_path();
    let collection = u8::from(collection_);
    let mut containers: AHashMap<u32, String> = AHashMap::with_capacity(16);
    let mut resources: AHashMap<u32, Vec<DavName>> = AHashMap::with_capacity(16);

    let mut time_ranges: AHashMap<u32, (i64, u32)> = AHashMap::new();
    let mut time_zones: AHashMap<u32, Tz> = AHashMap::new();

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
                    field: IDX_TIME,
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
                let field = key
                    .get(U32_LEN + 1)
                    .copied()
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

                if key_collection == collection {
                    if field == IDX_NAME {
                        containers.insert(
                            document_id,
                            std::str::from_utf8(value)
                                .map_err(|_| {
                                    trc::Error::corrupted_key(key, None, trc::location!())
                                })?
                                .to_string(),
                        );
                    } else if field == IDX_TIME {
                        let tz = Tz::from_id(key.deserialize_be_u16(IndexKeyPrefix::len())?)
                            .ok_or_else(|| {
                                trc::Error::corrupted_key(key, None, trc::location!())
                            })?;

                        time_zones.insert(document_id, tz);
                    }
                } else if field == IDX_NAME {
                    resources.entry(document_id).or_default().push(
                        DavName::deserialize(value)
                            .map_err(|_| trc::Error::corrupted_key(key, None, trc::location!()))?,
                    );
                } else if field == IDX_TIME {
                    let start_time = key.deserialize_be_u64(IndexKeyPrefix::len())?;
                    let duration = key.deserialize_be_u32(IndexKeyPrefix::len() + U64_LEN)?;

                    time_ranges.insert(document_id, (start_time as i64, duration));
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
                    data: time_ranges
                        .get(&document_id)
                        .map(|(start, duration)| DavResourceMetadata::CalendarEvent {
                            start: *start,
                            duration: *duration,
                        })
                        .unwrap_or(DavResourceMetadata::None),
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
            data: time_zones
                .get(&document_id)
                .map(|tz| DavResourceMetadata::Calendar { tz: *tz })
                .unwrap_or(DavResourceMetadata::None),
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
            DavResourceName::File.base_path(),
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
            data: DavResourceMetadata::File {
                size: expanded.size,
                hierarchy_sequence: expanded.hierarchy_sequence,
                is_container: expanded.is_container,
            },
        });
    }

    Ok(files)
}
