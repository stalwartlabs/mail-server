use std::ops::{BitAndAssign, BitXorAssign};

use foundationdb::{future::FdbValue, options, FdbResult, KeySelector, RangeOption};
use futures::{Stream, StreamExt};
use roaring::RoaringBitmap;
#[cfg(feature = "rocks")]
use rocksdb::{
    DBIteratorWithThreadMode, Direction, IteratorMode, MultiThreaded, OptimisticTransactionDB,
};

#[cfg(feature = "rocks")]
use crate::backend::rocksdb::{ACCOUNT_KEY_LEN, CF_INDEXES};

use crate::{
    backend::foundationdb::read::ReadTransaction, write::key::DeserializeBigEndian, Error,
    IndexKeyPrefix, Serialize, Store,
};

use super::{Comparator, ResultSet, SortedResultRet};

#[cfg(feature = "rocks")]
enum IndexType<'x> {
    DocumentSet {
        set: RoaringBitmap,
        it: Option<roaring::bitmap::IntoIter>,
    },
    DB {
        it: Option<DBIteratorWithThreadMode<'x, OptimisticTransactionDB<MultiThreaded>>>,
        prefix: Vec<u8>,
        from_key: Vec<u8>,
        ascending: bool,
        prev_item: Option<u32>,
        prev_key: Option<Box<[u8]>>,
    },
}

#[cfg(feature = "rocks")]
struct IndexIterator<'x> {
    index: IndexType<'x>,
    remaining: RoaringBitmap,
    eof: bool,
}

#[cfg(feature = "foundation")]
enum IndexType<'x, T: Stream<Item = FdbResult<FdbValue>> + Unpin + 'x> {
    DocumentSet {
        set: RoaringBitmap,
        it: Option<roaring::bitmap::IntoIter>,
    },
    DB {
        it: Option<T>,
        from_key: Vec<u8>,
        to_key: Vec<u8>,
        ascending: bool,
        prev_item: Option<u32>,
        prev_key: Option<Box<[u8]>>,
        phantom: std::marker::PhantomData<&'x ()>,
    },
}

#[cfg(feature = "foundation")]
struct IndexIterator<'x, T: Stream<Item = FdbResult<FdbValue>> + Unpin + 'x> {
    index: IndexType<'x, T>,
    remaining: RoaringBitmap,
    eof: bool,
}

impl Store {
    pub async fn sort(
        &self,
        mut result_set: ResultSet,
        comparators: Vec<Comparator>,
        limit: usize,
        mut position: i32,
        anchor: Option<u32>,
        mut anchor_offset: i32,
    ) -> crate::Result<SortedResultRet> {
        let has_anchor = anchor.is_some();
        let mut anchor_found = false;
        let requested_position = position;
        let trx = self.read_transaction().await?;

        let mut result = SortedResultRet {
            position,
            ids: Vec::with_capacity(std::cmp::min(limit, result_set.results.len() as usize)),
            found_anchor: true,
        };
        let mut iterators = comparators
            .into_iter()
            .map(|comp| IndexIterator {
                index: match comp {
                    Comparator::Field { field, ascending } => IndexType::DB {
                        it: None,
                        from_key: if !ascending {
                            result_set.from_key(field).serialize()
                        } else {
                            result_set.to_key(field).serialize()
                        },
                        to_key: if !ascending {
                            result_set.to_key(field).serialize()
                        } else {
                            result_set.from_key(field).serialize()
                        },
                        ascending,
                        prev_item: None,
                        prev_key: None,
                        phantom: std::marker::PhantomData,
                    },
                    Comparator::DocumentSet { mut set, ascending } => IndexType::DocumentSet {
                        set: if !ascending {
                            if !set.is_empty() {
                                set.bitxor_assign(&result_set.document_ids);
                                set
                            } else {
                                result_set.document_ids.clone()
                            }
                        } else {
                            set
                        },
                        it: None,
                    },
                },
                remaining: std::mem::replace(&mut result_set.results, RoaringBitmap::new()),
                eof: false,
            })
            .collect::<Vec<_>>();

        let mut current = 0;
        let iter_len = iterators.len() - 1;

        'outer: loop {
            let mut doc_id;

            'inner: loop {
                let (it_opts, mut next_it_opts) = if current < iter_len {
                    let (iterators_first, iterators_last) = iterators.split_at_mut(current + 1);
                    (
                        iterators_first.last_mut().unwrap(),
                        iterators_last.first_mut(),
                    )
                } else {
                    (&mut iterators[current], None)
                };

                if !matches!(it_opts.index, IndexType::DB {  prev_item,.. } if prev_item.is_some())
                {
                    if it_opts.remaining.is_empty() {
                        if current > 0 {
                            current -= 1;
                            continue 'inner;
                        } else {
                            break 'outer;
                        }
                    } else if it_opts.remaining.len() == 1 || it_opts.eof {
                        doc_id = it_opts.remaining.min().unwrap();
                        it_opts.remaining.remove(doc_id);
                        break 'inner;
                    }
                }

                match &mut it_opts.index {
                    IndexType::DB {
                        it,
                        from_key,
                        to_key,
                        ascending,
                        prev_item,
                        prev_key,
                        ..
                    } => {
                        let it = if let Some(it) = it {
                            it
                        } else {
                            #[cfg(feature = "foundation")]
                            {
                                *it = Some(trx.trx.get_ranges_keyvalues(
                                    RangeOption {
                                        begin: KeySelector::first_greater_or_equal(
                                            from_key.clone(),
                                        ),
                                        end: KeySelector::last_less_than(to_key.clone()),
                                        mode: options::StreamingMode::Iterator,
                                        reverse: !*ascending,
                                        ..Default::default()
                                    },
                                    true,
                                ));
                            }

                            #[cfg(feature = "rocks")]
                            {
                                *it = Some(self.db.iterator_cf(
                                    &self.db.cf_handle(CF_INDEXES).unwrap(),
                                    IteratorMode::From(
                                        from_key,
                                        if *ascending {
                                            Direction::Forward
                                        } else {
                                            Direction::Reverse
                                        },
                                    ),
                                ));
                            }
                            it.as_mut().unwrap()
                        };

                        let mut prev_key_prefix = prev_key
                            .as_ref()
                            .and_then(|k| k.get(..k.len() - std::mem::size_of::<u32>()))
                            .unwrap_or_default();

                        if let Some(prev_item) = prev_item.take() {
                            if let Some(next_it_opts) = &mut next_it_opts {
                                next_it_opts.remaining.insert(prev_item);
                            } else {
                                doc_id = prev_item;
                                break 'inner;
                            }
                        }

                        let mut is_eof = false;
                        loop {
                            if let Some(result) = it.next().await {
                                let key = result?.key().to_vec().into_boxed_slice();
                                /*let (key, _) = result.map_err(|e| {
                                    Error::InternalError(format!("Iterator error: {}", e))
                                })?;
                                if !key.starts_with(prefix) {
                                    *prev_key = None;
                                    is_eof = true;
                                    break;
                                }*/

                                doc_id = key
                                    .as_ref()
                                    .deserialize_be_u32(key.len() - std::mem::size_of::<u32>())?;
                                if it_opts.remaining.contains(doc_id) {
                                    it_opts.remaining.remove(doc_id);

                                    if let Some(next_it_opts) = &mut next_it_opts {
                                        if let Some(prev_key_) = &*prev_key {
                                            if key.len() != prev_key_.len()
                                                || !key.starts_with(prev_key_prefix)
                                            {
                                                *prev_item = Some(doc_id);
                                                *prev_key = Some(key);
                                                break;
                                            }
                                        } else {
                                            *prev_key = Some(key);
                                            prev_key_prefix = prev_key
                                                .as_ref()
                                                .and_then(|key| {
                                                    key.get(
                                                        ..key.len() - std::mem::size_of::<u32>(),
                                                    )
                                                })
                                                .ok_or_else(|| {
                                                    Error::InternalError(
                                                        "Invalid index entry".to_string(),
                                                    )
                                                })?;
                                        }

                                        next_it_opts.remaining.insert(doc_id);
                                    } else {
                                        // doc id found
                                        break 'inner;
                                    }
                                }
                            } else {
                                is_eof = true;
                                break;
                            }
                        }

                        if is_eof {
                            if let Some(next_it_opts) = &mut next_it_opts {
                                if !it_opts.remaining.is_empty() {
                                    next_it_opts.remaining |= &it_opts.remaining;
                                    it_opts.remaining.clear();
                                }
                                *prev_key = None;
                                it_opts.eof = true;
                            }
                        }
                    }
                    IndexType::DocumentSet { set, it } => {
                        if let Some(it) = it {
                            if let Some(_doc_id) = it.next() {
                                doc_id = _doc_id;
                                break 'inner;
                            }
                        } else {
                            let mut set = set.clone();
                            set.bitand_assign(&it_opts.remaining);
                            let set_len = set.len();
                            if set_len > 0 {
                                it_opts.remaining.bitxor_assign(&set);

                                match &mut next_it_opts {
                                    Some(next_it_opts) if set_len > 1 => {
                                        next_it_opts.remaining = set;
                                    }
                                    _ if set_len == 1 => {
                                        doc_id = set.min().unwrap();
                                        break 'inner;
                                    }
                                    _ => {
                                        let mut it_ = set.into_iter();
                                        let result = it_.next();
                                        *it = Some(it_);
                                        if let Some(result) = result {
                                            doc_id = result;
                                            break 'inner;
                                        } else {
                                            break 'outer;
                                        }
                                    }
                                }
                            } else if !it_opts.remaining.is_empty() {
                                if let Some(ref mut next_it_opts) = next_it_opts {
                                    next_it_opts.remaining = std::mem::take(&mut it_opts.remaining);
                                }
                            }
                        };
                    }
                };

                if let Some(next_it_opts) = next_it_opts {
                    if !next_it_opts.remaining.is_empty() {
                        if next_it_opts.remaining.len() == 1 {
                            doc_id = next_it_opts.remaining.min().unwrap();
                            next_it_opts.remaining.remove(doc_id);
                            break 'inner;
                        } else {
                            match &mut next_it_opts.index {
                                IndexType::DB {
                                    it,
                                    from_key,
                                    to_key,
                                    ascending,
                                    prev_item,
                                    prev_key,
                                    ..
                                } => {
                                    if let Some(it) = it {
                                        #[cfg(feature = "rocks")]
                                        {
                                            *it = self.db.iterator_cf(
                                                &self.db.cf_handle(CF_INDEXES).unwrap(),
                                                IteratorMode::From(
                                                    from_key,
                                                    if *ascending {
                                                        Direction::Forward
                                                    } else {
                                                        Direction::Reverse
                                                    },
                                                ),
                                            );
                                        }
                                        #[cfg(feature = "foundation")]
                                        {
                                            *it = trx.trx.get_ranges_keyvalues(
                                                RangeOption {
                                                    begin: KeySelector::first_greater_or_equal(
                                                        from_key.clone(),
                                                    ),
                                                    end: KeySelector::last_less_than(
                                                        to_key.clone(),
                                                    ),
                                                    mode: options::StreamingMode::Iterator,
                                                    reverse: !*ascending,
                                                    ..Default::default()
                                                },
                                                true,
                                            );
                                        }
                                    }
                                    *prev_item = None;
                                    *prev_key = None;
                                }
                                IndexType::DocumentSet { it, .. } => {
                                    *it = None;
                                }
                            }

                            current += 1;
                            next_it_opts.eof = false;
                            continue 'inner;
                        }
                    }
                }

                it_opts.eof = true;

                if it_opts.remaining.is_empty() {
                    if current > 0 {
                        current -= 1;
                    } else {
                        break 'outer;
                    }
                }
            }

            // Pagination
            if !has_anchor {
                if position >= 0 {
                    if position > 0 {
                        position -= 1;
                    } else {
                        result.ids.push(doc_id);
                        if limit > 0 && result.ids.len() == limit {
                            break 'outer;
                        }
                    }
                } else {
                    result.ids.push(doc_id);
                }
            } else if anchor_offset >= 0 {
                if !anchor_found {
                    if &doc_id != anchor.as_ref().unwrap() {
                        continue 'outer;
                    }
                    anchor_found = true;
                }

                if anchor_offset > 0 {
                    anchor_offset -= 1;
                } else {
                    result.ids.push(doc_id);
                    if limit > 0 && result.ids.len() == limit {
                        break 'outer;
                    }
                }
            } else {
                anchor_found = &doc_id == anchor.as_ref().unwrap();
                result.ids.push(doc_id);

                if !anchor_found {
                    continue 'outer;
                }

                position = anchor_offset;

                break 'outer;
            }
        }

        if !has_anchor || anchor_found {
            if !has_anchor && requested_position >= 0 {
                result.position = if position == 0 { requested_position } else { 0 };
            } else if position >= 0 {
                result.position = position;
            } else {
                let position = position.unsigned_abs() as usize;
                let start_offset = if position < result.ids.len() {
                    result.ids.len() - position
                } else {
                    0
                };
                result.position = start_offset as i32;
                let end_offset = if limit > 0 {
                    std::cmp::min(start_offset + limit, result.ids.len())
                } else {
                    result.ids.len()
                };

                result.ids = result.ids[start_offset..end_offset].to_vec()
            }
        } else {
            result.found_anchor = false;
        }

        Ok(result)
    }
}

impl ResultSet {
    pub fn from_key(&self, field: u8) -> IndexKeyPrefix {
        IndexKeyPrefix {
            account_id: self.account_id,
            collection: self.collection,
            field,
        }
    }
    pub fn to_key(&self, field: u8) -> IndexKeyPrefix {
        let (account_id, collection, field) = if field < u8::MAX {
            (self.account_id, self.collection, field + 1)
        } else if (self.collection) < u8::MAX {
            (self.account_id, (self.collection) + 1, field)
        } else {
            (self.account_id + 1, self.collection, field)
        };
        IndexKeyPrefix {
            account_id,
            collection,
            field,
        }
    }
}
