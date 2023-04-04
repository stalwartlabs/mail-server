use ahash::AHashMap;

use crate::{ReadTransaction, Store};

use super::{Comparator, ResultSet, SortedResultRet};

pub struct Pagination {
    requested_position: i32,
    position: i32,
    limit: usize,
    anchor: u32,
    anchor_offset: i32,
    has_anchor: bool,
    anchor_found: bool,
    ids: Vec<u32>,
}

impl ReadTransaction<'_> {
    #[maybe_async::maybe_async]
    pub async fn sort(
        &mut self,
        result_set: ResultSet,
        mut comparators: Vec<Comparator>,
        limit: usize,
        position: i32,
        anchor: Option<u32>,
        anchor_offset: i32,
    ) -> crate::Result<SortedResultRet> {
        let mut paginate = Pagination::new(limit, position, anchor, anchor_offset);

        if comparators.len() == 1 {
            match comparators.pop().unwrap() {
                Comparator::Field { field, ascending } => {
                    let mut results = result_set.results;

                    self.sort_index(
                        result_set.account_id,
                        result_set.collection,
                        field,
                        ascending,
                        |_, document_id| !results.remove(document_id) || paginate.add(document_id),
                    )
                    .await?;

                    // Add remaining items not present in the index
                    if !results.is_empty() && !paginate.is_full() {
                        for document_id in results {
                            if !paginate.add(document_id) {
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
                            if !paginate.add(document_id) {
                                break 'outer;
                            }
                        }
                    }
                }
            }
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

            let mut sorted_ids = sorted_ids.into_iter().collect::<Vec<_>>();
            sorted_ids.sort_by(|a, b| a.1.cmp(&b.1));
            for (document_id, _) in sorted_ids {
                if !paginate.add(document_id) {
                    break;
                }
            }
        }

        Ok(paginate.build())
    }
}

impl Store {
    pub async fn sort(
        &self,
        result_set: ResultSet,
        comparators: Vec<Comparator>,
        limit: usize,
        position: i32,
        anchor: Option<u32>,
        anchor_offset: i32,
    ) -> crate::Result<SortedResultRet> {
        let limit = match (result_set.results.len(), limit) {
            (0, _) => {
                return Ok(SortedResultRet {
                    position,
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
                .sort(
                    result_set,
                    comparators,
                    limit,
                    position,
                    anchor,
                    anchor_offset,
                )
                .await
        }

        #[cfg(feature = "is_sync")]
        {
            let mut trx = self.read_transaction()?;
            self.spawn_worker(move || {
                trx.sort(
                    result_set,
                    comparators,
                    limit,
                    position,
                    anchor,
                    anchor_offset,
                )
            })
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
        }
    }

    pub fn add(&mut self, document_id: u32) -> bool {
        // Pagination
        if !self.has_anchor {
            if self.position > 0 {
                self.position -= 1;
            } else {
                self.ids.push(document_id);
                if self.ids.len() == self.limit {
                    return false;
                }
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
                self.ids.push(document_id);
                if self.ids.len() == self.limit {
                    return false;
                }
            }
        } else {
            self.anchor_found = document_id == self.anchor;
            self.ids.push(document_id);

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

    pub fn build(self) -> SortedResultRet {
        let mut result = SortedResultRet {
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
