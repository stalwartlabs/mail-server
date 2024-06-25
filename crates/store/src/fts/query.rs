/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt::Display,
    ops::{BitAndAssign, BitOrAssign, BitXorAssign},
};

use ahash::AHashMap;
use nlp::language::stemmer::Stemmer;
use roaring::RoaringBitmap;

use crate::{
    backend::MAX_TOKEN_LENGTH,
    fts::FtsFilter,
    write::{
        hash::TokenType, key::DeserializeBigEndian, BitmapHash, DynamicDocumentId, ValueClass,
    },
    BitmapKey, IterateParams, Store, ValueKey, U32_LEN,
};

use super::postings::SerializedPostings;

struct State {
    pub op: FtsTokenized,
    pub bm: Option<RoaringBitmap>,
}

enum FtsTokenized {
    Exact {
        tokens: Vec<(BitmapHash, u8)>,
    },
    Contains {
        field: u8,
        tokens: Vec<(BitmapHash, Option<BitmapHash>)>,
    },
    Keyword {
        field: u8,
        token: BitmapHash,
    },
    And,
    Or,
    Not,
    End,
}

impl Store {
    pub async fn fts_query<T: Into<u8> + Display + Clone + std::fmt::Debug>(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
        filters: Vec<FtsFilter<T>>,
    ) -> crate::Result<RoaringBitmap> {
        let collection = collection.into();

        // Tokenize text
        let mut tokenized_filters = Vec::with_capacity(filters.len());
        let mut token_count = AHashMap::new();
        for filter in filters {
            let filter = match filter {
                FtsFilter::Exact {
                    field,
                    text,
                    language,
                } => {
                    let mut tokens = Vec::new();
                    let field = TokenType::word(field.into());

                    for token in language.tokenize_text(text.as_ref(), MAX_TOKEN_LENGTH) {
                        let hash = BitmapHash::new(token.word.as_ref());
                        token_count.entry(hash).and_modify(|c| *c += 1).or_insert(1);
                        tokens.push((hash, field));
                    }
                    FtsTokenized::Exact { tokens }
                }
                FtsFilter::Contains {
                    field,
                    text,
                    language,
                } => {
                    let mut tokens = Vec::new();
                    for token in Stemmer::new(text.as_ref(), language, MAX_TOKEN_LENGTH) {
                        let hash = BitmapHash::new(token.word.as_ref());
                        let stemmed_hash = token.stemmed_word.as_deref().map(BitmapHash::new);

                        token_count.entry(hash).and_modify(|c| *c += 1).or_insert(1);
                        if let Some(stemmed_hash) = stemmed_hash {
                            token_count
                                .entry(stemmed_hash)
                                .and_modify(|c| *c += 1)
                                .or_insert(1);
                        }

                        tokens.push((hash, stemmed_hash));
                    }
                    FtsTokenized::Contains {
                        field: field.into(),
                        tokens,
                    }
                }
                FtsFilter::Keyword { field, text } => {
                    let hash = BitmapHash::new(text);
                    token_count.entry(hash).and_modify(|c| *c += 1).or_insert(1);

                    FtsTokenized::Keyword {
                        field: field.into(),
                        token: hash,
                    }
                }
                FtsFilter::And => FtsTokenized::And,
                FtsFilter::Or => FtsTokenized::Or,
                FtsFilter::Not => FtsTokenized::Not,
                FtsFilter::End => FtsTokenized::End,
            };

            tokenized_filters.push(filter);
        }

        let mut not_mask = RoaringBitmap::new();
        let mut not_fetch = false;

        let mut state: State = FtsTokenized::And.into();
        let mut stack = Vec::new();
        let mut token_cache = AHashMap::with_capacity(token_count.len());
        let mut filters = tokenized_filters.into_iter().peekable();

        while let Some(filter) = filters.next() {
            let mut result = match filter {
                FtsTokenized::Exact { tokens } => {
                    self.get_postings(
                        account_id,
                        collection,
                        &tokens,
                        &token_count,
                        &mut token_cache,
                        true,
                    )
                    .await?
                }
                FtsTokenized::Contains { field, tokens } => {
                    let mut result = RoaringBitmap::new();

                    for (token, stemmed_token) in tokens {
                        match self
                            .get_postings(
                                account_id,
                                collection,
                                &[
                                    (token, TokenType::word(field)),
                                    (stemmed_token.unwrap_or(token), TokenType::stemmed(field)),
                                ],
                                &token_count,
                                &mut token_cache,
                                false,
                            )
                            .await?
                        {
                            Some(b) if !b.is_empty() => {
                                if !result.is_empty() {
                                    result &= b;
                                    if result.is_empty() {
                                        break;
                                    }
                                } else {
                                    result = b;
                                }
                            }
                            _ => break,
                        }
                    }

                    if !result.is_empty() {
                        Some(result)
                    } else {
                        None
                    }
                }
                FtsTokenized::Keyword { field, token } => {
                    self.get_postings(
                        account_id,
                        collection,
                        &[(token, TokenType::word(field))],
                        &token_count,
                        &mut token_cache,
                        false,
                    )
                    .await?
                }
                op @ (FtsTokenized::And | FtsTokenized::Or | FtsTokenized::Not) => {
                    stack.push(state);
                    state = op.into();
                    continue;
                }
                FtsTokenized::End => {
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
            if matches!(state.op, FtsTokenized::Not) && !not_fetch {
                not_mask = self
                    .get_bitmap(BitmapKey::document_ids(account_id, collection))
                    .await?
                    .unwrap_or_else(RoaringBitmap::new);
                not_fetch = true;
            }

            // Apply logical operation
            if let Some(dest) = &mut state.bm {
                match state.op {
                    FtsTokenized::And => {
                        if let Some(result) = result {
                            dest.bitand_assign(result);
                        } else {
                            dest.clear();
                        }
                    }
                    FtsTokenized::Or => {
                        if let Some(result) = result {
                            dest.bitor_assign(result);
                        }
                    }
                    FtsTokenized::Not => {
                        if let Some(mut result) = result {
                            result.bitxor_assign(&not_mask);
                            dest.bitand_assign(result);
                        }
                    }
                    _ => unreachable!(),
                }
            } else if let Some(ref mut result_) = result {
                if let FtsTokenized::Not = state.op {
                    result_.bitxor_assign(&not_mask);
                }
                state.bm = result;
            } else if let FtsTokenized::Not = state.op {
                state.bm = Some(not_mask.clone());
            } else {
                state.bm = Some(RoaringBitmap::new());
            }

            // And short circuit
            if matches!(state.op, FtsTokenized::And) && state.bm.as_ref().unwrap().is_empty() {
                while let Some(filter) = filters.peek() {
                    if matches!(filter, FtsTokenized::End) {
                        break;
                    } else {
                        filters.next();
                    }
                }
            }
        }

        Ok(state.bm.unwrap_or_default())
    }

    async fn get_postings(
        &self,
        account_id: u32,
        collection: u8,
        tokens: &[(BitmapHash, u8)],
        token_count: &AHashMap<BitmapHash, u32>,
        token_cache: &mut AHashMap<BitmapHash, AHashMap<u32, SerializedPostings<Vec<u8>>>>,
        is_intersect: bool,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let mut result_bm = RoaringBitmap::new();
        let mut position_candidates = AHashMap::new();
        let num_tokens = tokens.len();

        for (pos, (token, field)) in tokens.iter().enumerate() {
            let needs_caching = token_count[token] > 1;
            let is_first = pos == 0;
            let mut bm = RoaringBitmap::new();

            if needs_caching {
                // Try to fetch from cache
                if let Some(postings) = token_cache.get(token) {
                    for (document_id, postings) in postings {
                        if postings.has_field(*field) {
                            if is_intersect {
                                if is_first {
                                    if num_tokens > 1 {
                                        position_candidates
                                            .insert(*document_id, postings.positions());
                                    }
                                    bm.insert(*document_id);
                                } else if position_candidates
                                    .get(document_id)
                                    .map_or(false, |positions| {
                                        postings.matches_positions(positions, pos as u32)
                                    })
                                {
                                    bm.insert(*document_id);
                                }
                            } else {
                                result_bm.insert(*document_id);
                            }
                        }
                    }

                    if is_intersect {
                        if is_first {
                            result_bm = bm;
                        } else {
                            result_bm &= bm;
                        }
                        if result_bm.is_empty() {
                            return Ok(None);
                        }
                    }

                    continue;
                }

                // Insert empty cache entry
                token_cache.insert(*token, AHashMap::new());
            }

            // Fetch from store
            let key_len = ValueClass::FtsIndex::<DynamicDocumentId>(*token).serialized_size();
            self.iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection,
                        document_id: 0,
                        class: ValueClass::FtsIndex(*token),
                    },
                    ValueKey {
                        account_id,
                        collection,
                        document_id: u32::MAX,
                        class: ValueClass::FtsIndex(*token),
                    },
                ),
                |key, value| {
                    if key.len() != key_len {
                        return Ok(true);
                    }

                    // Make sure this document contain the field
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    let postings = SerializedPostings::new(value);
                    if postings.has_field(*field) {
                        if is_intersect {
                            if is_first {
                                if num_tokens > 1 {
                                    position_candidates.insert(document_id, postings.positions());
                                }
                                bm.insert(document_id);
                            } else if position_candidates
                                .get(&document_id)
                                .map_or(false, |positions| {
                                    postings.matches_positions(positions, pos as u32)
                                })
                            {
                                bm.insert(document_id);
                            }
                        } else {
                            result_bm.insert(document_id);
                        }
                    }

                    // Cache the postings if needed
                    if needs_caching {
                        token_cache
                            .entry(*token)
                            .or_default()
                            .insert(document_id, SerializedPostings::new(value.to_vec()));
                    }

                    Ok(true)
                },
            )
            .await?;

            if is_intersect {
                if is_first {
                    result_bm = bm;
                } else {
                    result_bm &= bm;
                }
                if result_bm.is_empty() {
                    return Ok(None);
                }
            }
        }

        Ok(if !result_bm.is_empty() {
            Some(result_bm)
        } else {
            None
        })
    }
}

impl From<FtsTokenized> for State {
    fn from(value: FtsTokenized) -> Self {
        Self {
            op: value,
            bm: None,
        }
    }
}
