/*
 * Copyright (c) 2023, Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use roaring::RoaringBitmap;

use crate::BitmapKey;

use super::SqliteStore;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct IdCacheKey {
    pub account_id: u32,
    pub collection: u8,
}

impl IdCacheKey {
    pub fn new(account_id: u32, collection: impl Into<u8>) -> Self {
        Self {
            account_id,
            collection: collection.into(),
        }
    }
}

#[derive(Clone)]
pub struct IdAssigner {
    pub freed_document_ids: Option<RoaringBitmap>,
    pub next_document_id: u32,
}

impl IdAssigner {
    pub fn new(used_ids: Option<RoaringBitmap>) -> Self {
        let mut assigner = IdAssigner {
            freed_document_ids: None,
            next_document_id: 0,
        };
        if let Some(used_ids) = used_ids {
            if let Some(max) = used_ids.max() {
                assigner.next_document_id = max + 1;
                let mut freed_ids =
                    RoaringBitmap::from_sorted_iter(0..assigner.next_document_id).unwrap();
                freed_ids ^= used_ids;
                if !freed_ids.is_empty() {
                    assigner.freed_document_ids = Some(freed_ids);
                }
            }
        }

        assigner
    }

    pub fn assign_document_id(&mut self) -> u32 {
        if let Some(freed_ids) = &mut self.freed_document_ids {
            let id = freed_ids.min().unwrap();
            freed_ids.remove(id);
            if freed_ids.is_empty() {
                self.freed_document_ids = None;
            }
            id
        } else {
            let id = self.next_document_id;
            self.next_document_id += 1;
            id
        }
    }
}

impl SqliteStore {
    pub(crate) async fn assign_document_id(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
    ) -> crate::Result<u32> {
        let key = IdCacheKey::new(account_id, collection.into());
        for _ in 0..2 {
            if let Some(assigner) = self.id_assigner.lock().get_mut(&key) {
                return Ok(assigner.assign_document_id());
            }
            self.build_id_assigner(key).await?;
        }

        unreachable!()
    }

    pub(crate) async fn build_id_assigner(&self, key: IdCacheKey) -> crate::Result<()> {
        // Obtain used ids
        let used_ids = self
            .get_bitmap(BitmapKey::document_ids(key.account_id, key.collection))
            .await?;

        let id_assigner = self.id_assigner.clone();
        let mut id_assigner = id_assigner.lock();
        // Make sure id assigner was not added by another thread
        if id_assigner.get_mut(&key).is_none() {
            id_assigner.insert(key, IdAssigner::new(used_ids));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use roaring::RoaringBitmap;

    use super::IdAssigner;

    #[test]
    fn id_assigner() {
        let mut assigner = IdAssigner::new(None);
        assert_eq!(assigner.assign_document_id(), 0);
        assert_eq!(assigner.assign_document_id(), 1);
        assert_eq!(assigner.assign_document_id(), 2);

        let mut assigner = IdAssigner::new(
            RoaringBitmap::from_sorted_iter([0, 2, 4, 6])
                .unwrap()
                .into(),
        );
        assert_eq!(assigner.assign_document_id(), 1);
        assert_eq!(assigner.assign_document_id(), 3);
        assert_eq!(assigner.assign_document_id(), 5);
        assert_eq!(assigner.assign_document_id(), 7);
        assert_eq!(assigner.assign_document_id(), 8);
    }
}
