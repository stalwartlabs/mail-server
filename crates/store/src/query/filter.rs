/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::{BitAndAssign, BitOrAssign, BitXorAssign};

use ahash::HashSet;
use nlp::tokenizers::word::WordTokenizer;
use roaring::RoaringBitmap;
use trc::AddContext;

use crate::{
    backend::MAX_TOKEN_LENGTH, write::key::DeserializeBigEndian, BitmapKey, IndexKey,
    IndexKeyPrefix, IterateParams, Key, Store, U32_LEN,
};

use super::{Filter, Operator, ResultSet};

struct State {
    pub op: Filter,
    pub bm: Option<RoaringBitmap>,
}

impl Store {
    pub async fn filter(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
        filters: Vec<Filter>,
    ) -> trc::Result<ResultSet> {
        let collection = collection.into();
        if filters.is_empty() {
            return Ok(ResultSet {
                account_id,
                collection,
                results: self
                    .get_bitmap(BitmapKey::document_ids(account_id, collection))
                    .await
                    .caused_by(trc::location!())?
                    .unwrap_or_else(RoaringBitmap::new),
            });
        }

        let mut state: State = Filter::And.into();
        let mut stack = Vec::new();
        let mut filters = filters.into_iter().peekable();

        let mut not_mask = RoaringBitmap::new();
        let mut not_fetch = false;

        while let Some(filter) = filters.next() {
            let mut result = match filter {
                Filter::MatchValue { field, op, value } => self
                    .range_to_bitmap(account_id, collection, field, &value, op)
                    .await
                    .caused_by(trc::location!())?,
                Filter::HasText {
                    field,
                    text,
                    tokenize,
                } => {
                    if tokenize {
                        self.get_bitmaps_intersection(
                            WordTokenizer::new(&text, MAX_TOKEN_LENGTH)
                                .map(|token| token.word.into_owned())
                                .collect::<HashSet<String>>()
                                .into_iter()
                                .map(|word| {
                                    BitmapKey::text_token(account_id, collection, field, word)
                                })
                                .collect(),
                        )
                        .await
                        .caused_by(trc::location!())?
                    } else {
                        self.get_bitmap(BitmapKey::text_token(account_id, collection, field, text))
                            .await
                            .caused_by(trc::location!())?
                    }
                }
                Filter::InBitmap(class) => self
                    .get_bitmap(BitmapKey {
                        account_id,
                        collection,
                        class,
                        document_id: 0,
                    })
                    .await
                    .caused_by(trc::location!())?,
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

            // Only fetch not mask if we need it
            if matches!(state.op, Filter::Not) && !not_fetch {
                not_mask = self
                    .get_bitmap(BitmapKey::document_ids(account_id, collection))
                    .await
                    .caused_by(trc::location!())?
                    .unwrap_or_else(RoaringBitmap::new);
                not_fetch = true;
            }

            // Apply logical operation
            if let Some(dest) = &mut state.bm {
                match state.op {
                    Filter::And => {
                        if let Some(result) = result {
                            dest.bitand_assign(result);
                        } else {
                            dest.clear();
                        }
                    }
                    Filter::Or => {
                        if let Some(result) = result {
                            dest.bitor_assign(result);
                        }
                    }
                    Filter::Not => {
                        if let Some(mut result) = result {
                            result.bitxor_assign(&not_mask);
                            dest.bitand_assign(result);
                        }
                    }
                    _ => unreachable!(),
                }
            } else if let Some(ref mut result_) = result {
                if let Filter::Not = state.op {
                    result_.bitxor_assign(&not_mask);
                }
                state.bm = result;
            } else if let Filter::Not = state.op {
                state.bm = Some(not_mask.clone());
            } else {
                state.bm = Some(RoaringBitmap::new());
            }

            // And short-circuit
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
            results: state.bm.unwrap_or_default(),
        })
    }

    async fn range_to_bitmap(
        &self,
        account_id: u32,
        collection: u8,
        field: u8,
        match_value: &[u8],
        op: Operator,
    ) -> trc::Result<Option<RoaringBitmap>> {
        let (begin, end) = match op {
            Operator::LowerThan => (
                IndexKey {
                    account_id,
                    collection,
                    document_id: 0,
                    field,
                    key: &[][..],
                },
                IndexKey {
                    account_id,
                    collection,
                    document_id: 0,
                    field,
                    key: match_value,
                },
            ),
            Operator::LowerEqualThan => (
                IndexKey {
                    account_id,
                    collection,
                    document_id: 0,
                    field,
                    key: &[][..],
                },
                IndexKey {
                    account_id,
                    collection,
                    document_id: u32::MAX,
                    field,
                    key: match_value,
                },
            ),
            Operator::GreaterThan => (
                IndexKey {
                    account_id,
                    collection,
                    document_id: u32::MAX,
                    field,
                    key: match_value,
                },
                IndexKey {
                    account_id,
                    collection,
                    document_id: u32::MAX,
                    field: field + 1,
                    key: &[][..],
                },
            ),
            Operator::GreaterEqualThan => (
                IndexKey {
                    account_id,
                    collection,
                    document_id: 0,
                    field,
                    key: match_value,
                },
                IndexKey {
                    account_id,
                    collection,
                    document_id: u32::MAX,
                    field: field + 1,
                    key: &[][..],
                },
            ),
            Operator::Equal => (
                IndexKey {
                    account_id,
                    collection,
                    document_id: 0,
                    field,
                    key: match_value,
                },
                IndexKey {
                    account_id,
                    collection,
                    document_id: u32::MAX,
                    field,
                    key: match_value,
                },
            ),
        };

        let mut bm = RoaringBitmap::new();
        let prefix = IndexKeyPrefix {
            account_id,
            collection,
            field,
        }
        .serialize(0);

        self.iterate(
            IterateParams::new(begin, end).no_values().ascending(),
            |key, _| {
                if !key.starts_with(&prefix) {
                    return Ok(false);
                }

                let id_pos = key.len() - U32_LEN;
                let value = key
                    .get(IndexKeyPrefix::len()..id_pos)
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

                let matches = match op {
                    Operator::LowerThan => value < match_value,
                    Operator::LowerEqualThan => value <= match_value,
                    Operator::GreaterThan => value > match_value,
                    Operator::GreaterEqualThan => value >= match_value,
                    Operator::Equal => value == match_value,
                };

                if matches {
                    bm.insert(key.deserialize_be_u32(id_pos)?);
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        if !bm.is_empty() {
            Ok(Some(bm))
        } else {
            Ok(None)
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
