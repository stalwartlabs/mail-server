/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use std::cmp::Ordering;

use ahash::{AHashMap, AHashSet};

use crate::{ReadTransaction, Store, ValueKey};

use super::{Comparator, ResultSet, SortedResultSet};

pub struct Pagination {
    requested_position: i32,
    position: i32,
    pub limit: usize,
    anchor: u32,
    anchor_offset: i32,
    has_anchor: bool,
    anchor_found: bool,
    ids: Vec<u64>,
    prefix_key: Option<ValueKey>,
    prefix_unique: bool,
}

impl ReadTransaction<'_> {
    #[maybe_async::maybe_async]
    pub async fn sort(
        &mut self,
        result_set: ResultSet,
        mut comparators: Vec<Comparator>,
        mut paginate: Pagination,
    ) -> crate::Result<SortedResultSet> {
        if comparators.len() == 1 && !paginate.prefix_unique {
            match comparators.pop().unwrap() {
                Comparator::Field { field, ascending } => {
                    let mut results = result_set.results;

                    self.sort_index(
                        result_set.account_id,
                        result_set.collection,
                        field,
                        ascending,
                        |_, document_id| {
                            !results.remove(document_id) || paginate.add(0, document_id)
                        },
                    )
                    .await?;

                    // Add remaining items not present in the index
                    if !results.is_empty() && !paginate.is_full() {
                        for document_id in results {
                            if !paginate.add(0, document_id) {
                                break;
                            }
                        }
                    }
                }
                Comparator::DocumentSet { set, ascending } => {
                    let in_set = &result_set.results & &set;
                    let not_in_set = &result_set.results ^ &in_set;
                    let sets = if ascending {
                        [in_set, not_in_set]
                    } else {
                        [not_in_set, in_set]
                    };
                    'outer: for set in sets {
                        for document_id in set {
                            if !paginate.add(0, document_id) {
                                break 'outer;
                            }
                        }
                    }
                }
            }

            // Obtain prefixes
            let prefix_key = paginate.prefix_key.take();
            let mut sorted_results = paginate.build();
            if let Some(prefix_key) = prefix_key {
                for id in sorted_results.ids.iter_mut() {
                    if let Some(prefix_id) = self
                        .get_value::<u32>(prefix_key.with_document_id(*id as u32))
                        .await?
                    {
                        *id |= (prefix_id as u64) << 32;
                    }
                }
            }

            Ok(sorted_results)
        } else {
            let mut sorted_ids = AHashMap::with_capacity(paginate.limit);

            for (pos, comparator) in comparators.into_iter().take(4).enumerate() {
                match comparator {
                    Comparator::Field { field, ascending } => {
                        let mut results = result_set.results.clone();
                        let mut prev_data = vec![];
                        let mut has_grouped_ids = false;
                        let mut idx = 0;

                        self.refresh_if_old().await?;
                        self.sort_index(
                            result_set.account_id,
                            result_set.collection,
                            field,
                            ascending,
                            |data, document_id| {
                                if results.remove(document_id) {
                                    debug_assert!(!data.is_empty());

                                    if data != prev_data {
                                        idx += 1;
                                        prev_data = data.to_vec();
                                    } else {
                                        has_grouped_ids = true;
                                    }

                                    sorted_ids.entry(document_id).or_insert([0u32; 4])[pos] = idx;

                                    !results.is_empty()
                                } else {
                                    true
                                }
                            },
                        )
                        .await?;

                        // Add remaining items not present in the index
                        if !results.is_empty() {
                            idx += 1;
                            for document_id in results {
                                sorted_ids.entry(document_id).or_insert([0u32; 4])[pos] = idx;
                            }
                        }

                        if !has_grouped_ids {
                            // If we are sorting by multiple fields and we don't have grouped ids, we can
                            // stop here
                            break;
                        }
                    }
                    Comparator::DocumentSet { set, ascending } => {
                        let in_set = &result_set.results & &set;
                        let not_in_set = &result_set.results ^ &in_set;
                        let sets = if ascending {
                            [(in_set, 0), (not_in_set, 1)]
                        } else {
                            [(not_in_set, 0), (in_set, 1)]
                        };

                        for (document_ids, idx) in sets {
                            for document_id in document_ids {
                                sorted_ids.entry(document_id).or_insert([0u32; 4])[pos] = idx;
                            }
                        }
                    }
                }
            }

            let mut seen_prefixes = AHashSet::new();
            let mut sorted_ids = sorted_ids.into_iter().collect::<Vec<_>>();
            sorted_ids.sort_by(|a, b| match a.1.cmp(&b.1) {
                Ordering::Equal => a.0.cmp(&b.0),
                other => other,
            });
            for (document_id, _) in sorted_ids {
                // Obtain document prefixId
                let prefix_id = if let Some(prefix_key) = &paginate.prefix_key {
                    if let Some(prefix_id) = self
                        .get_value(prefix_key.with_document_id(document_id))
                        .await?
                    {
                        if paginate.prefix_unique && !seen_prefixes.insert(prefix_id) {
                            continue;
                        }
                        prefix_id
                    } else {
                        // Document no longer exists?
                        continue;
                    }
                } else {
                    0
                };

                // Add document to results
                if !paginate.add(prefix_id, document_id) {
                    break;
                }
            }

            Ok(paginate.build())
        }
    }
}

impl Store {
    pub async fn sort(
        &self,
        result_set: ResultSet,
        comparators: Vec<Comparator>,
        mut paginate: Pagination,
    ) -> crate::Result<SortedResultSet> {
        paginate.limit = match (result_set.results.len(), paginate.limit) {
            (0, _) => {
                return Ok(SortedResultSet {
                    position: paginate.position,
                    ids: vec![],
                    found_anchor: true,
                });
            }
            (_, 0) => result_set.results.len() as usize,
            (a, b) => std::cmp::min(a as usize, b),
        };

        #[cfg(feature = "is_async")]
        {
            self.read_transaction()
                .await?
                .sort(result_set, comparators, paginate)
                .await
        }

        #[cfg(feature = "is_sync")]
        {
            let mut trx = self.read_transaction()?;
            self.spawn_worker(move || trx.sort(result_set, comparators, paginate))
                .await
        }
    }
}

impl Pagination {
    pub fn new(limit: usize, position: i32, anchor: Option<u32>, anchor_offset: i32) -> Self {
        let (has_anchor, anchor) = anchor.map(|anchor| (true, anchor)).unwrap_or((false, 0));

        Self {
            requested_position: position,
            position,
            limit,
            anchor,
            anchor_offset,
            has_anchor,
            anchor_found: false,
            ids: Vec::with_capacity(limit),
            prefix_key: None,
            prefix_unique: false,
        }
    }

    pub fn with_prefix_key(mut self, prefix_key: ValueKey) -> Self {
        self.prefix_key = Some(prefix_key);
        self
    }

    pub fn with_prefix_unique(mut self, prefix_unique: bool) -> Self {
        self.prefix_unique = prefix_unique;
        self
    }

    pub fn add(&mut self, prefix_id: u32, document_id: u32) -> bool {
        let id = ((prefix_id as u64) << 32) | document_id as u64;

        // Pagination
        if !self.has_anchor {
            if self.position >= 0 {
                if self.position > 0 {
                    self.position -= 1;
                } else {
                    self.ids.push(id);
                    if self.ids.len() == self.limit {
                        return false;
                    }
                }
            } else {
                self.ids.push(id);
            }
        } else if self.anchor_offset >= 0 {
            if !self.anchor_found {
                if document_id != self.anchor {
                    return true;
                }
                self.anchor_found = true;
            }

            if self.anchor_offset > 0 {
                self.anchor_offset -= 1;
            } else {
                self.ids.push(id);
                if self.ids.len() == self.limit {
                    return false;
                }
            }
        } else {
            self.anchor_found = document_id == self.anchor;
            self.ids.push(id);

            if self.anchor_found {
                self.position = self.anchor_offset;
                return false;
            }
        }

        true
    }

    pub fn is_full(&self) -> bool {
        self.ids.len() == self.limit
    }

    pub fn build(self) -> SortedResultSet {
        let mut result = SortedResultSet {
            ids: self.ids,
            position: 0,
            found_anchor: !self.has_anchor || self.anchor_found,
        };

        if result.found_anchor {
            if !self.has_anchor && self.requested_position >= 0 {
                result.position = if self.position == 0 {
                    self.requested_position
                } else {
                    0
                };
            } else if self.position >= 0 {
                result.position = self.position;
            } else {
                let position = self.position.unsigned_abs() as usize;
                let start_offset = if position < result.ids.len() {
                    result.ids.len() - position
                } else {
                    0
                };
                result.position = start_offset as i32;
                let end_offset = if self.limit > 0 {
                    std::cmp::min(start_offset + self.limit, result.ids.len())
                } else {
                    result.ids.len()
                };

                result.ids = result.ids[start_offset..end_offset].to_vec()
            }
        }

        result
    }
}
