use std::{
    ops::{BitAndAssign, BitOrAssign, BitXorAssign},
    time::Instant,
};

use roaring::RoaringBitmap;

use crate::{
    backend::foundationdb::read::ReadTransaction, write::Tokenize, BitmapKey, Store, BM_TERM,
    TERM_EXACT,
};

use super::{Filter, ResultSet};

struct State {
    op: Filter,
    bm: Option<RoaringBitmap>,
}

impl Store {
    pub async fn filter(
        &self,
        account_id: u32,
        collection: u8,
        filters: Vec<Filter>,
    ) -> crate::Result<ResultSet> {
        let mut trx = self.read_transaction().await?;
        let document_ids = trx
            .get_document_ids(account_id, collection)
            .await?
            .unwrap_or_else(RoaringBitmap::new);
        if filters.is_empty() {
            return Ok(ResultSet {
                account_id,
                collection,
                results: document_ids.clone(),
                document_ids,
            });
        }

        let mut state: State = Filter::And.into();
        let mut stack = Vec::new();
        let mut filters = filters.into_iter().peekable();

        while let Some(filter) = filters.next() {
            trx.refresh_if_old().await?;

            let result = match filter {
                Filter::HasKeyword { field, value } => {
                    trx.get_bitmap(BitmapKey {
                        account_id,
                        collection,
                        family: BM_TERM | TERM_EXACT,
                        field,
                        key: value.as_bytes(),
                        #[cfg(feature = "foundation")]
                        block_num: 0,
                    })
                    .await?
                }
                Filter::HasKeywords { field, value } => {
                    trx.get_bitmaps_intersection(
                        value
                            .tokenize()
                            .into_iter()
                            .map(|key| BitmapKey {
                                account_id,
                                collection,
                                family: BM_TERM | TERM_EXACT,
                                field,
                                key: key.into_bytes(),
                                #[cfg(feature = "foundation")]
                                block_num: 0,
                            })
                            .collect(),
                    )
                    .await?
                }
                Filter::MatchValue { field, op, value } => {
                    trx.range_to_bitmap(account_id, collection, field, value, op)
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
                    trx.get_bitmap(BitmapKey {
                        account_id,
                        collection,
                        family,
                        field,
                        key: &key,
                        #[cfg(feature = "foundation")]
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

            state.op.apply(&mut state.bm, result, &document_ids);

            //println!("{:?}: {:?}", state.op, state.bm);

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
            document_ids,
        })
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
