/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use trc::AddContext;
use utils::codec::leb128::Leb128Iterator;

use crate::{IterateParams, LogKey, Store, U32_LEN, U64_LEN, write::key::DeserializeBigEndian};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Change {
    InsertContainer(u64),
    UpdateContainer(u64),
    UpdateContainerProperty(u64),
    DeleteContainer(u64),
    InsertItem(u64),
    UpdateItem(u64),
    DeleteItem(u64),
}

#[derive(Debug)]
pub struct Changes {
    pub changes: Vec<Change>,
    pub from_change_id: u64,
    pub to_change_id: u64,
    pub container_change_id: Option<u64>,
    pub item_change_id: Option<u64>,
    pub is_truncated: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Query {
    All,
    Since(u64),
    SinceInclusive(u64),
    RangeInclusive(u64, u64),
}

pub trait DeserializeVanished: Sized + Sync + Send {
    fn deserialize_vanished<'x>(bytes: &mut impl Iterator<Item = &'x u8>) -> Option<Self>;
}

impl Default for Changes {
    fn default() -> Self {
        Self {
            changes: Vec::with_capacity(10),
            from_change_id: 0,
            to_change_id: 0,
            container_change_id: None,
            item_change_id: None,
            is_truncated: false,
        }
    }
}

impl Store {
    pub async fn changes(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
        query: Query,
    ) -> trc::Result<Changes> {
        let collection = collection.into();
        let (is_inclusive, from_change_id, to_change_id) = match query {
            Query::All => (true, 0, u64::MAX),
            Query::Since(change_id) => (false, change_id, u64::MAX),
            Query::SinceInclusive(change_id) => (true, change_id, u64::MAX),
            Query::RangeInclusive(from_change_id, to_change_id) => {
                (true, from_change_id, to_change_id)
            }
        };
        let from_key = LogKey {
            account_id,
            collection,
            change_id: from_change_id,
        };
        let to_key = LogKey {
            account_id,
            collection,
            change_id: to_change_id,
        };

        let mut changelog = Changes::default();

        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
                if is_inclusive || change_id != from_change_id {
                    if value.is_empty() {
                        changelog.is_truncated = true;
                        return Ok(true);
                    }
                    if changelog.changes.is_empty() {
                        changelog.from_change_id = change_id;
                    }
                    changelog.to_change_id = change_id;
                    let (has_container_changes, has_item_changes) =
                        changelog.deserialize(value).ok_or_else(|| {
                            trc::Error::corrupted_key(key, value.into(), trc::location!())
                        })?;
                    if has_container_changes {
                        changelog.container_change_id = Some(change_id);
                    }
                    if has_item_changes {
                        changelog.item_change_id = Some(change_id);
                    }
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        if changelog.changes.is_empty() {
            changelog.from_change_id = from_change_id;
            changelog.to_change_id = if to_change_id != u64::MAX {
                to_change_id
            } else {
                from_change_id
            };
        }

        Ok(changelog)
    }

    pub async fn vanished<T: DeserializeVanished>(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
        query: Query,
    ) -> trc::Result<Vec<T>> {
        let collection = collection.into();
        let (is_inclusive, from_change_id, to_change_id) = match query {
            Query::All => (true, 0, u64::MAX),
            Query::Since(change_id) => (false, change_id, u64::MAX),
            Query::SinceInclusive(change_id) => (true, change_id, u64::MAX),
            Query::RangeInclusive(from_change_id, to_change_id) => {
                (true, from_change_id, to_change_id)
            }
        };
        let from_key = LogKey {
            account_id,
            collection,
            change_id: from_change_id,
        };
        let to_key = LogKey {
            account_id,
            collection,
            change_id: to_change_id,
        };

        let mut vanished = Vec::default();

        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
                if is_inclusive || change_id != from_change_id {
                    let mut iter = value.iter().peekable();

                    while iter.peek().is_some() {
                        if let Some(item) = T::deserialize_vanished(&mut iter) {
                            vanished.push(item);
                        } else {
                            return Err(trc::Error::corrupted_key(
                                key,
                                value.into(),
                                trc::location!(),
                            ));
                        }
                    }
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(vanished)
    }

    pub async fn get_last_change_id(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
    ) -> trc::Result<Option<u64>> {
        let collection = collection.into();

        let from_key = LogKey {
            account_id,
            collection,
            change_id: 0,
        };
        let to_key = LogKey {
            account_id,
            collection,
            change_id: u64::MAX,
        };

        let mut last_change_id = None;

        self.iterate(
            IterateParams::new(from_key, to_key)
                .descending()
                .no_values()
                .only_first(),
            |key, _| {
                last_change_id = key.deserialize_be_u64(key.len() - U64_LEN)?.into();
                Ok(false)
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(last_change_id)
    }
}

impl Changes {
    pub fn deserialize(&mut self, bytes: &[u8]) -> Option<(bool, bool)> {
        let mut bytes_it = bytes.iter();

        let container_inserts: usize = bytes_it.next_leb128()?;
        let container_updates: usize = bytes_it.next_leb128()?;
        let container_property_changes: usize = bytes_it.next_leb128()?;
        let container_deletes: usize = bytes_it.next_leb128()?;

        let item_inserts: usize = bytes_it.next_leb128()?;
        let item_updates: usize = bytes_it.next_leb128()?;
        let item_deletes: usize = bytes_it.next_leb128()?;

        let has_container_changes =
            container_inserts + container_updates + container_property_changes + container_deletes
                > 0;
        let has_item_changes = item_inserts + item_updates + item_deletes > 0;

        if container_inserts > 0 {
            for _ in 0..container_inserts {
                self.changes
                    .push(Change::InsertContainer(bytes_it.next_leb128()?));
            }
        }

        if container_updates > 0 || container_property_changes > 0 {
            'update_outer: for change_pos in 0..(container_updates + container_property_changes) {
                let id = bytes_it.next_leb128()?;
                let mut is_property_change = change_pos >= container_updates;

                for (idx, change) in self.changes.iter().enumerate() {
                    match change {
                        Change::InsertContainer(insert_id) if *insert_id == id => {
                            // Item updated after inserted, no need to count this change.
                            continue 'update_outer;
                        }
                        Change::UpdateContainer(update_id) if *update_id == id => {
                            // Move update to the front
                            is_property_change = false;
                            self.changes.remove(idx);
                            break;
                        }
                        Change::UpdateContainerProperty(update_id) if *update_id == id => {
                            // Move update to the front
                            self.changes.remove(idx);
                            break;
                        }
                        _ => (),
                    }
                }

                self.changes.push(if !is_property_change {
                    Change::UpdateContainer(id)
                } else {
                    Change::UpdateContainerProperty(id)
                });
            }
        }

        if container_deletes > 0 {
            'delete_outer: for _ in 0..container_deletes {
                let id = bytes_it.next_leb128()?;

                'delete_inner: for (idx, change) in self.changes.iter().enumerate() {
                    match change {
                        Change::InsertContainer(insert_id) if *insert_id == id => {
                            self.changes.remove(idx);
                            continue 'delete_outer;
                        }
                        Change::UpdateContainer(update_id) if *update_id == id => {
                            self.changes.remove(idx);
                            break 'delete_inner;
                        }
                        _ => (),
                    }
                }

                self.changes.push(Change::DeleteContainer(id));
            }
        }

        // Item changes
        if item_inserts > 0 {
            for _ in 0..item_inserts {
                self.changes
                    .push(Change::InsertItem(bytes_it.next_leb128()?));
            }
        }

        if item_updates > 0 {
            'update_outer: for _ in 0..item_updates {
                let id = bytes_it.next_leb128()?;

                for (idx, change) in self.changes.iter().enumerate() {
                    match change {
                        Change::InsertItem(insert_id) if *insert_id == id => {
                            // Item updated after inserted, no need to count this change.
                            continue 'update_outer;
                        }
                        Change::UpdateItem(update_id) if *update_id == id => {
                            // Move update to the front
                            self.changes.remove(idx);
                            break;
                        }
                        _ => (),
                    }
                }

                self.changes.push(Change::UpdateItem(id));
            }
        }

        if item_deletes > 0 {
            'delete_outer: for _ in 0..item_deletes {
                let id = bytes_it.next_leb128()?;

                'delete_inner: for (idx, change) in self.changes.iter().enumerate() {
                    match change {
                        Change::InsertItem(insert_id) if *insert_id == id => {
                            self.changes.remove(idx);
                            continue 'delete_outer;
                        }
                        Change::UpdateItem(update_id) if *update_id == id => {
                            self.changes.remove(idx);
                            break 'delete_inner;
                        }
                        _ => (),
                    }
                }

                self.changes.push(Change::DeleteItem(id));
            }
        }

        Some((has_container_changes, has_item_changes))
    }
}

impl Changes {
    pub fn total_container_changes(&self) -> usize {
        self.changes
            .iter()
            .filter(|change| change.is_container_change())
            .count()
    }

    pub fn total_item_changes(&self) -> usize {
        self.changes
            .iter()
            .filter(|change| change.is_item_change())
            .count()
    }
}

impl Change {
    pub fn item_id(&self) -> Option<u64> {
        match self {
            Change::InsertItem(id) => Some(*id),
            Change::UpdateItem(id) => Some(*id),
            Change::DeleteItem(id) => Some(*id),
            _ => None,
        }
    }

    pub fn container_id(&self) -> Option<u64> {
        match self {
            Change::InsertContainer(id) => Some(*id),
            Change::UpdateContainer(id) => Some(*id),
            Change::UpdateContainerProperty(id) => Some(*id),
            Change::DeleteContainer(id) => Some(*id),
            _ => None,
        }
    }

    pub fn try_unwrap_item_id(self) -> Option<u64> {
        match self {
            Change::InsertItem(id) => Some(id),
            Change::UpdateItem(id) => Some(id),
            Change::DeleteItem(id) => Some(id),
            _ => None,
        }
    }

    pub fn try_unwrap_container_id(self) -> Option<u64> {
        match self {
            Change::InsertContainer(id) => Some(id),
            Change::UpdateContainer(id) => Some(id),
            Change::UpdateContainerProperty(id) => Some(id),
            Change::DeleteContainer(id) => Some(id),
            _ => None,
        }
    }

    pub fn is_container_change(&self) -> bool {
        matches!(
            self,
            Change::InsertContainer(_)
                | Change::UpdateContainer(_)
                | Change::UpdateContainerProperty(_)
                | Change::DeleteContainer(_)
        )
    }

    pub fn is_item_change(&self) -> bool {
        matches!(
            self,
            Change::InsertItem(_) | Change::UpdateItem(_) | Change::DeleteItem(_)
        )
    }
}

impl DeserializeVanished for u64 {
    fn deserialize_vanished<'x>(bytes: &mut impl Iterator<Item = &'x u8>) -> Option<Self> {
        let mut num = [0u8; U64_LEN];
        for i in num.iter_mut() {
            *i = *bytes.next()?;
        }
        Some(u64::from_be_bytes(num))
    }
}

impl DeserializeVanished for (u32, u32) {
    fn deserialize_vanished<'x>(bytes: &mut impl Iterator<Item = &'x u8>) -> Option<Self> {
        let mut num1 = [0u8; U32_LEN];
        let mut num2 = [0u8; U32_LEN];
        for i in num1.iter_mut().chain(num2.iter_mut()) {
            *i = *bytes.next()?;
        }
        Some((u32::from_be_bytes(num1), u32::from_be_bytes(num2)))
    }
}

impl DeserializeVanished for String {
    fn deserialize_vanished<'x>(bytes: &mut impl Iterator<Item = &'x u8>) -> Option<Self> {
        let mut name = Vec::with_capacity(16);

        loop {
            let byte = bytes.next()?;
            if *byte != 0 {
                name.push(*byte);
            } else {
                break;
            }
        }

        String::from_utf8(name).ok()
    }
}
