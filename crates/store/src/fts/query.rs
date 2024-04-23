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

use std::{
    borrow::Cow,
    fmt::Display,
    ops::{BitAndAssign, BitOrAssign, BitXorAssign},
};

use ahash::AHashSet;
use nlp::language::stemmer::Stemmer;
use roaring::RoaringBitmap;
use utils::codec::leb128::Leb128Reader;

use crate::{
    backend::MAX_TOKEN_LENGTH,
    fts::FtsFilter,
    write::{BitmapClass, BitmapHash, ValueClass},
    BitmapKey, Deserialize, Error, Store, ValueKey,
};

use super::index::TERM_INDEX_VERSION;

struct State<T: Into<u8> + Display + Clone + std::fmt::Debug> {
    pub op: FtsFilter<T>,
    pub bm: Option<RoaringBitmap>,
}

struct BigramIndex {
    grams: Vec<[u8; 8]>,
}

impl Store {
    pub async fn fts_query<T: Into<u8> + Display + Clone + std::fmt::Debug>(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
        filters: Vec<FtsFilter<T>>,
    ) -> crate::Result<RoaringBitmap> {
        let collection = collection.into();
        let mut not_mask = RoaringBitmap::new();
        let mut not_fetch = false;

        let mut state: State<T> = FtsFilter::And.into();
        let mut stack = Vec::new();
        let mut filters = filters.into_iter().peekable();

        while let Some(filter) = filters.next() {
            let mut result = match filter {
                FtsFilter::Exact {
                    field,
                    text,
                    language,
                } => {
                    let field: u8 = field.clone().into();
                    let mut keys = Vec::new();
                    let mut bigrams = AHashSet::new();
                    let mut last_token = Cow::Borrowed("");
                    for token in language.tokenize_text(text.as_ref(), MAX_TOKEN_LENGTH) {
                        keys.push(BitmapKey {
                            account_id,
                            collection,
                            class: BitmapClass::word(token.word.as_ref(), field),
                            document_id: 0,
                        });

                        if !last_token.is_empty() {
                            bigrams.insert(
                                BitmapHash::new(&format!("{} {}", last_token, token.word)).hash,
                            );
                        }

                        last_token = token.word;
                    }

                    match keys.len().cmp(&1) {
                        std::cmp::Ordering::Less => None,
                        std::cmp::Ordering::Equal => self.get_bitmaps_intersection(keys).await?,
                        std::cmp::Ordering::Greater => {
                            if let Some(document_ids) = self.get_bitmaps_intersection(keys).await? {
                                let mut results = RoaringBitmap::new();
                                for document_id in document_ids {
                                    if let Some(bigram_index) = self
                                        .get_value::<BigramIndex>(ValueKey {
                                            account_id,
                                            collection,
                                            document_id,
                                            class: ValueClass::TermIndex,
                                        })
                                        .await?
                                    {
                                        if bigrams.iter().all(|bigram| {
                                            bigram_index.grams.binary_search(bigram).is_ok()
                                        }) {
                                            results.insert(document_id);
                                        }
                                    }
                                }

                                if !results.is_empty() {
                                    Some(results)
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                    }
                }
                FtsFilter::Contains {
                    field,
                    text,
                    language,
                } => {
                    let mut result = RoaringBitmap::new();
                    let field: u8 = field.clone().into();

                    for token in Stemmer::new(text.as_ref(), language, MAX_TOKEN_LENGTH) {
                        let token1 = BitmapKey {
                            account_id,
                            collection,
                            class: BitmapClass::word(token.word.as_ref(), field),
                            document_id: 0,
                        };
                        let token2 = BitmapKey {
                            account_id,
                            collection,
                            class: BitmapClass::stemmed(
                                if let Some(stemmed_word) = token.stemmed_word {
                                    stemmed_word
                                } else {
                                    token.word
                                }
                                .as_ref(),
                                field,
                            ),
                            document_id: 0,
                        };

                        match self.get_bitmaps_union(vec![token1, token2]).await? {
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
                FtsFilter::Keyword { field, text } => {
                    self.get_bitmap(BitmapKey {
                        account_id,
                        collection,
                        class: BitmapClass::word(text, field),
                        document_id: 0,
                    })
                    .await?
                }
                op @ (FtsFilter::And | FtsFilter::Or | FtsFilter::Not) => {
                    stack.push(state);
                    state = op.into();
                    continue;
                }
                FtsFilter::End => {
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
            if matches!(state.op, FtsFilter::Not) && !not_fetch {
                not_mask = self
                    .get_bitmap(BitmapKey::document_ids(account_id, collection))
                    .await?
                    .unwrap_or_else(RoaringBitmap::new);
                not_fetch = true;
            }

            // Apply logical operation
            if let Some(dest) = &mut state.bm {
                match state.op {
                    FtsFilter::And => {
                        if let Some(result) = result {
                            dest.bitand_assign(result);
                        } else {
                            dest.clear();
                        }
                    }
                    FtsFilter::Or => {
                        if let Some(result) = result {
                            dest.bitor_assign(result);
                        }
                    }
                    FtsFilter::Not => {
                        if let Some(mut result) = result {
                            result.bitxor_assign(&not_mask);
                            dest.bitand_assign(result);
                        }
                    }
                    _ => unreachable!(),
                }
            } else if let Some(ref mut result_) = result {
                if let FtsFilter::Not = state.op {
                    result_.bitxor_assign(&not_mask);
                }
                state.bm = result;
            } else if let FtsFilter::Not = state.op {
                state.bm = Some(not_mask.clone());
            } else {
                state.bm = Some(RoaringBitmap::new());
            }

            // And short circuit
            if matches!(state.op, FtsFilter::And) && state.bm.as_ref().unwrap().is_empty() {
                while let Some(filter) = filters.peek() {
                    if matches!(filter, FtsFilter::End) {
                        break;
                    } else {
                        filters.next();
                    }
                }
            }
        }

        Ok(state.bm.unwrap_or_default())
    }

    async fn get_bitmaps_union(
        &self,
        keys: Vec<BitmapKey<BitmapClass<u32>>>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let mut bm = RoaringBitmap::new();

        for key in keys {
            if let Some(items) = self.get_bitmap(key).await? {
                bm.bitor_assign(items);
            }
        }

        Ok(if !bm.is_empty() { Some(bm) } else { None })
    }
}

impl Deserialize for BigramIndex {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.first().copied().unwrap_or_default() != TERM_INDEX_VERSION {
            return Err(Error::InternalError(
                "Unsupported term index version".to_string(),
            ));
        }
        let bytes = lz4_flex::decompress_size_prepended(bytes.get(1..).unwrap_or_default())
            .map_err(|_| Error::InternalError("Failed to decompress term index".to_string()))?;

        let (num_items, pos) = bytes.read_leb128::<usize>().ok_or(Error::InternalError(
            "Failed to read term index marker".to_string(),
        ))?;

        bytes
            .get(pos..pos + (num_items * 8))
            .map(|bytes| Self {
                grams: bytes
                    .chunks_exact(8)
                    .map(|chunk| chunk.try_into().unwrap())
                    .collect(),
            })
            .ok_or_else(|| Error::InternalError("Failed to read term index".to_string()))
    }
}

impl<T: Into<u8> + Display + Clone + std::fmt::Debug> From<FtsFilter<T>> for State<T> {
    fn from(value: FtsFilter<T>) -> Self {
        Self {
            op: value,
            bm: None,
        }
    }
}
