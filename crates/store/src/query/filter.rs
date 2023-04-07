use std::ops::{BitAndAssign, BitOrAssign, BitXorAssign};

use ahash::HashSet;
use roaring::RoaringBitmap;

use crate::{
    fts::{builder::MAX_TOKEN_LENGTH, tokenizers::space::SpaceTokenizer},
    BitmapKey, ReadTransaction, Store, BM_KEYWORD,
};

use super::{Filter, ResultSet};

struct State {
    op: Filter,
    bm: Option<RoaringBitmap>,
}

impl ReadTransaction<'_> {
    #[maybe_async::maybe_async]
    pub async fn filter(
        &mut self,
        account_id: u32,
        collection: u8,
        filters: Vec<Filter>,
    ) -> crate::Result<ResultSet> {
        let mut not_mask = RoaringBitmap::new();
        let mut not_fetch = false;
        if filters.is_empty() {
            return Ok(ResultSet {
                account_id,
                collection,
                results: self
                    .get_bitmap(BitmapKey::new_document_ids(account_id, collection))
                    .await?
                    .unwrap_or_else(RoaringBitmap::new),
            });
        }

        let mut state: State = Filter::And.into();
        let mut stack = Vec::new();
        let mut filters = filters.into_iter().peekable();

        while let Some(filter) = filters.next() {
            self.refresh_if_old().await?;

            let result = match filter {
                Filter::HasKeyword { field, value } => {
                    self.get_bitmap(BitmapKey {
                        account_id,
                        collection,
                        family: BM_KEYWORD,
                        field,
                        key: value.as_bytes(),
                        block_num: 0,
                    })
                    .await?
                }
                Filter::HasKeywords { field, value } => {
                    self.get_bitmaps_intersection(
                        SpaceTokenizer::new(&value, MAX_TOKEN_LENGTH)
                            .collect::<HashSet<String>>()
                            .into_iter()
                            .map(|word| BitmapKey::hash(&word, account_id, collection, 0, field))
                            .collect(),
                    )
                    .await?
                }
                Filter::MatchValue { field, op, value } => {
                    self.range_to_bitmap(account_id, collection, field, value, op)
                        .await?
                }
                Filter::HasText {
                    field,
                    text,
                    language,
                    match_phrase,
                } => {
                    self.fts_query(account_id, collection, field, &text, language, match_phrase)
                        .await?
                }
                Filter::InBitmap { family, field, key } => {
                    self.get_bitmap(BitmapKey {
                        account_id,
                        collection,
                        family,
                        field,
                        key: &key,
                        block_num: 0,
                    })
                    .await?
                }
                Filter::DocumentSet(set) => Some(set),
                op @ (Filter::And | Filter::Or | Filter::Not) => {
                    stack.push(state);
                    state = op.into();
                    continue;
                }
                Filter::End => {
                    if let Some(prev_state) = stack.pop() {
                        let bm = state.bm;
                        state = prev_state;
                        bm
                    } else {
                        break;
                    }
                }
            };

            if matches!(state.op, Filter::Not) && !not_fetch {
                not_mask = self
                    .get_bitmap(BitmapKey::new_document_ids(account_id, collection))
                    .await?
                    .unwrap_or_else(RoaringBitmap::new);
                not_fetch = true;
            }

            state.op.apply(&mut state.bm, result, &not_mask);

            if matches!(state.op, Filter::And) && state.bm.as_ref().unwrap().is_empty() {
                while let Some(filter) = filters.peek() {
                    if matches!(filter, Filter::End) {
                        break;
                    } else {
                        filters.next();
                    }
                }
            }
        }

        Ok(ResultSet {
            account_id,
            collection,
            results: state.bm.unwrap_or_else(RoaringBitmap::new),
        })
    }
}

impl Store {
    pub async fn filter(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
        filters: Vec<Filter>,
    ) -> crate::Result<ResultSet> {
        let collection = collection.into();
        #[cfg(feature = "is_async")]
        {
            self.read_transaction()
                .await?
                .filter(account_id, collection, filters)
                .await
        }

        #[cfg(feature = "is_sync")]
        {
            let mut trx = self.read_transaction()?;
            self.spawn_worker(move || trx.filter(account_id, collection, filters))
                .await
        }
    }
}

impl Filter {
    #[inline(always)]
    pub fn apply(
        &self,
        dest: &mut Option<RoaringBitmap>,
        mut src: Option<RoaringBitmap>,
        not_mask: &RoaringBitmap,
    ) {
        if let Some(dest) = dest {
            match self {
                Filter::And => {
                    if let Some(src) = src {
                        dest.bitand_assign(src);
                    } else {
                        dest.clear();
                    }
                }
                Filter::Or => {
                    if let Some(src) = src {
                        dest.bitor_assign(src);
                    }
                }
                Filter::Not => {
                    if let Some(mut src) = src {
                        src.bitxor_assign(not_mask);
                        dest.bitand_assign(src);
                    }
                }
                _ => unreachable!(),
            }
        } else if let Some(ref mut src_) = src {
            if let Filter::Not = self {
                src_.bitxor_assign(not_mask);
            }
            *dest = src;
        } else if let Filter::Not = self {
            *dest = Some(not_mask.clone());
        } else {
            *dest = Some(RoaringBitmap::new());
        }
    }
}

impl From<Filter> for State {
    fn from(value: Filter) -> Self {
        Self {
            op: value,
            bm: None,
        }
    }
}
