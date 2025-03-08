/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use jmap_proto::types::{collection::Collection, property::Property};
use store::{
    Deserialize, IndexKey, IterateParams, SerializeInfallible, U32_LEN, ValueKey,
    write::{Archive, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use utils::topological::{TopologicalSort, TopologicalSortIterator};

use crate::Server;

pub struct ExpandedFolders {
    names: AHashMap<u32, ExpandedFolder>,
    iter: TopologicalSortIterator<u32>,
}

#[derive(Debug, Clone)]
pub struct ExpandedFolder {
    pub name: String,
    pub document_id: u32,
    pub parent_id: Option<u32>,
    pub is_container: bool,
    pub size: u32,
    pub hierarchy_sequence: u32,
}

pub trait FolderHierarchy: Sync + Send {
    fn name(&self) -> String;
    fn parent_id(&self) -> u32;
    fn is_container(&self) -> bool;
    fn size(&self) -> u32;
}

pub trait TopologyBuilder: Sync + Send {
    fn insert(&mut self, folder_id: u32, parent_id: u32);
}

impl Server {
    pub async fn fetch_folders<T>(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> trc::Result<ExpandedFolders>
    where
        T: rkyv::Archive,
        T::Archived: FolderHierarchy
            + for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        let collection_: u8 = collection.into();

        let mut names = AHashMap::with_capacity(10);
        let mut topological_sort = TopologicalSort::with_capacity(10);

        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection: collection_,
                        document_id: 0,
                        class: ValueClass::Property(Property::Value.into()),
                    },
                    ValueKey {
                        account_id,
                        collection: collection_,
                        document_id: u32::MAX,
                        class: ValueClass::Property(Property::Value.into()),
                    },
                ),
                |key, value| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    let archive = <Archive as Deserialize>::deserialize(value)?;
                    let folder = archive.unarchive::<T>()?;
                    let parent_id = folder.parent_id();

                    topological_sort.insert(parent_id, document_id + 1);
                    names.insert(
                        document_id,
                        ExpandedFolder {
                            name: folder.name(),
                            document_id,
                            parent_id: if parent_id > 0 {
                                Some(parent_id - 1)
                            } else {
                                None
                            },
                            is_container: folder.is_container(),
                            size: folder.size(),
                            hierarchy_sequence: 0,
                        },
                    );

                    Ok(true)
                },
            )
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })?;

        Ok(ExpandedFolders {
            names,
            iter: topological_sort.into_iterator(),
        })
    }

    pub async fn fetch_folder_topology<T>(
        &self,
        account_id: u32,
        collection: Collection,
        topology: &mut impl TopologyBuilder,
    ) -> trc::Result<()>
    where
        T: TopologyBuilder,
    {
        self.store()
            .iterate(
                IterateParams::new(
                    IndexKey {
                        account_id,
                        collection: collection.into(),
                        document_id: 0,
                        field: Property::ParentId.into(),
                        key: 0u32.serialize(),
                    },
                    IndexKey {
                        account_id,
                        collection: collection.into(),
                        document_id: u32::MAX,
                        field: Property::ParentId.into(),
                        key: u32::MAX.serialize(),
                    },
                )
                .no_values()
                .ascending(),
                |key, _| {
                    let document_id = key
                        .get(key.len() - U32_LEN..)
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))
                        .and_then(u32::deserialize)?;
                    let parent_id = key
                        .get(key.len() - (U32_LEN * 2)..key.len() - U32_LEN)
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))
                        .and_then(u32::deserialize)?;

                    topology.insert(document_id, parent_id);

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }
}

impl ExpandedFolders {
    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn format<T>(mut self, formatter: T) -> Self
    where
        T: Fn(&mut ExpandedFolder),
    {
        for folder in self.names.values_mut() {
            formatter(folder);
        }
        self
    }

    pub fn into_iterator(mut self) -> impl Iterator<Item = ExpandedFolder> + Sync + Send {
        for (hierarchy_sequence, folder_id) in self.iter.by_ref().enumerate() {
            if folder_id != 0 {
                let folder_id = folder_id - 1;
                if let Some((name, parent_name)) = self
                    .names
                    .get(&folder_id)
                    .and_then(|folder| folder.parent_id.map(|parent_id| (&folder.name, parent_id)))
                    .and_then(|(name, parent_id)| {
                        self.names
                            .get(&parent_id)
                            .map(|folder| (name, &folder.name))
                    })
                {
                    let name = format!("{parent_name}/{name}");
                    let folder = self.names.get_mut(&folder_id).unwrap();
                    folder.name = name;
                    folder.hierarchy_sequence = hierarchy_sequence as u32;
                } else {
                    self.names.get_mut(&folder_id).unwrap().hierarchy_sequence =
                        hierarchy_sequence as u32;
                }
            }
        }

        self.names.into_values()
    }
}
