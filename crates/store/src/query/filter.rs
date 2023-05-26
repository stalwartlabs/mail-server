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

use std::ops::{BitAndAssign, BitOrAssign, BitXorAssign};

use ahash::HashSet;
use roaring::RoaringBitmap;

use crate::{
    fts::{builder::MAX_TOKEN_LENGTH, tokenizers::space::SpaceTokenizer},
    BitmapKey, ReadTransaction, Store,
};

use super::{Filter, ResultSet, TextMatch};

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
                    .get_bitmap(BitmapKey::document_ids(account_id, collection))
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
                Filter::MatchValue { field, op, value } => {
                    self.range_to_bitmap(account_id, collection, field, value, op)
                        .await?
                }
                Filter::HasText { field, text, op } => match op {
                    TextMatch::Exact(language) => {
                        self.fts_query(account_id, collection, field, &text, language, true)
                            .await?
                    }
                    TextMatch::Stemmed(language) => {
                        self.fts_query(account_id, collection, field, &text, language, false)
                            .await?
                    }
                    TextMatch::Tokenized => {
                        self.get_bitmaps_intersection(
                            SpaceTokenizer::new(&text, MAX_TOKEN_LENGTH)
                                .collect::<HashSet<String>>()
                                .into_iter()
                                .map(|word| {
                                    BitmapKey::hash(&word, account_id, collection, 0, field)
                                })
                                .collect(),
                        )
                        .await?
                    }
                    TextMatch::Raw => {
                        self.get_bitmap(BitmapKey::hash(&text, account_id, collection, 0, field))
                            .await?
                    }
                },
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
                    .get_bitmap(BitmapKey::document_ids(account_id, collection))
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
