/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::slice::IterMut;

use jmap_proto::types::property::Property;
use store::{
    Serialize, SerializedVersion,
    write::{Archive, Archiver, BatchBuilder, TagValue, ValueClass},
};

pub struct TagManager<
    T: Into<TagValue>
        + PartialEq
        + Clone
        + Sync
        + Send
        + rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
> {
    current: Archive<Vec<T>>,
    added: Vec<T>,
    removed: Vec<T>,
    last: LastTag,
}

enum LastTag {
    Set,
    Update,
    None,
}

impl<
    T: Into<TagValue>
        + PartialEq
        + Clone
        + Sync
        + Send
        + SerializedVersion
        + rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
> TagManager<T>
{
    pub fn new(current: Archive<Vec<T>>) -> Self {
        Self {
            current,
            added: Vec::new(),
            removed: Vec::new(),
            last: LastTag::None,
        }
    }

    pub fn set(&mut self, tags: Vec<T>) {
        if matches!(self.last, LastTag::None) {
            self.added.clear();
            self.removed.clear();

            for tag in &tags {
                if !self.current.inner.contains(tag) {
                    self.added.push(tag.clone());
                }
            }

            for tag in &self.current.inner {
                if !tags.contains(tag) {
                    self.removed.push(tag.clone());
                }
            }

            self.current.inner = tags;
            self.last = LastTag::Set;
        }
    }

    pub fn update(&mut self, tag: T, add: bool) {
        if matches!(self.last, LastTag::None | LastTag::Update) {
            if add {
                if !self.current.inner.contains(&tag) {
                    self.added.push(tag.clone());
                    self.current.inner.push(tag);
                }
            } else if let Some(index) = self.current.inner.iter().position(|t| t == &tag) {
                self.current.inner.swap_remove(index);
                self.removed.push(tag);
            }
            self.last = LastTag::Update;
        }
    }

    pub fn added(&self) -> &[T] {
        &self.added
    }

    pub fn removed(&self) -> &[T] {
        &self.removed
    }

    pub fn current(&self) -> &[T] {
        &self.current.inner
    }

    pub fn changed_tags(&self) -> impl Iterator<Item = &T> {
        self.added.iter().chain(self.removed.iter())
    }

    pub fn inner_tags_mut(&mut self) -> IterMut<'_, T> {
        self.current.inner.iter_mut()
    }

    pub fn has_tags(&self) -> bool {
        !self.current.inner.is_empty()
    }

    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty()
    }

    pub fn update_batch(self, batch: &mut BatchBuilder, property: Property) -> trc::Result<()> {
        let property = u8::from(property);

        batch
            .assert_value(ValueClass::Property(property), &self.current)
            .set(
                ValueClass::Property(property),
                Archiver::new(self.current.inner).serialize()?,
            );
        for added in self.added {
            batch.tag(property, added);
        }
        for removed in self.removed {
            batch.untag(property, removed);
        }

        Ok(())
    }
}
