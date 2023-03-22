use std::{
    borrow::Cow,
    ops::{BitAndAssign, BitOrAssign, BitXorAssign},
};

use ahash::AHashSet;
use roaring::RoaringBitmap;

use crate::{
    fts::{
        index::MAX_TOKEN_LENGTH, stemmer::Stemmer, term_index::TermIndex, tokenizers::Tokenizer,
    },
    write::Tokenize,
    BitmapKey, Error, IndexKey, Store, ValueKey, BM_TERM, TERM_EXACT, TERM_STEMMED,
};

use super::{Filter, ResultSet};

struct State {
    op: Filter,
    bm: Option<RoaringBitmap>,
}

impl Store {
    pub fn filter(
        &self,
        account_id: u32,
        collection: u8,
        filters: Vec<Filter>,
    ) -> crate::Result<ResultSet> {
        let document_ids = self
            .get_document_ids(account_id, collection)?
            .unwrap_or_else(RoaringBitmap::new);
        let mut state: State = Filter::And.into();
        let mut stack = Vec::new();
        let mut filters = filters.into_iter().peekable();

        while let Some(filter) = filters.next() {
            match filter {
                Filter::HasKeyword { field, value } => {
                    state.op.apply(
                        &mut state.bm,
                        self.get_bitmap(BitmapKey {
                            account_id,
                            collection,
                            family: BM_TERM | TERM_EXACT,
                            field,
                            key: value.as_bytes(),
                        })?,
                        &document_ids,
                    );
                }
                Filter::HasKeywords { field, value } => {
                    let tokens = value.tokenize();
                    state.op.apply(
                        &mut state.bm,
                        self.get_bitmaps_intersection(
                            tokens
                                .iter()
                                .map(|key| BitmapKey {
                                    account_id,
                                    collection,
                                    family: BM_TERM | TERM_EXACT,
                                    field,
                                    key,
                                })
                                .collect(),
                        )?,
                        &document_ids,
                    );
                }
                Filter::MatchValue { field, op, value } => {
                    state.op.apply(
                        &mut state.bm,
                        self.range_to_bitmap(
                            IndexKey {
                                account_id,
                                collection,
                                field,
                                key: &value,
                            },
                            op,
                        )?,
                        &document_ids,
                    );
                }
                Filter::HasText {
                    field,
                    text,
                    language,
                    match_phrase,
                } => {
                    if match_phrase {
                        let phrase = Tokenizer::new(&text, language, MAX_TOKEN_LENGTH)
                            .map(|token| token.word)
                            .collect::<Vec<_>>();
                        let mut keys = Vec::with_capacity(phrase.len());

                        for word in &phrase {
                            let key = BitmapKey {
                                account_id,
                                collection,
                                family: BM_TERM | TERM_EXACT,
                                field,
                                key: word.as_bytes(),
                            };
                            if !keys.contains(&key) {
                                keys.push(key);
                            }
                        }

                        // Retrieve the Term Index for each candidate and match the exact phrase
                        if let Some(candidates) = self.get_bitmaps_intersection(keys)? {
                            let mut results = RoaringBitmap::new();
                            for document_id in candidates.iter() {
                                if let Some(term_index) = self.get_value::<TermIndex>(ValueKey {
                                    account_id,
                                    collection,
                                    document_id,
                                    field: u8::MAX,
                                })? {
                                    if term_index
                                        .match_terms(
                                            &phrase
                                                .iter()
                                                .map(|w| term_index.get_match_term(w, None))
                                                .collect::<Vec<_>>(),
                                            None,
                                            true,
                                            false,
                                            false,
                                        )
                                        .map_err(|e| {
                                            Error::InternalError(format!(
                                                "Corrupted TermIndex for {}: {:?}",
                                                document_id, e
                                            ))
                                        })?
                                        .is_some()
                                    {
                                        results.insert(document_id);
                                    }
                                }
                            }
                            state.op.apply(&mut state.bm, results.into(), &document_ids);
                        } else {
                            state.op.apply(&mut state.bm, None, &document_ids);
                        }
                    } else {
                        let words = Stemmer::new(&text, language, MAX_TOKEN_LENGTH)
                            .map(|token| (token.word, token.stemmed_word.unwrap_or(Cow::from(""))))
                            .collect::<AHashSet<_>>();
                        let mut requested_keys = AHashSet::default();
                        let mut text_bitmap = None;

                        for (word, stemmed_word) in &words {
                            let mut keys = Vec::new();

                            for (word, family) in [
                                (word, BM_TERM | TERM_EXACT),
                                (word, BM_TERM | TERM_STEMMED),
                                (stemmed_word, BM_TERM | TERM_EXACT),
                                (stemmed_word, BM_TERM | TERM_STEMMED),
                            ] {
                                if !word.is_empty() {
                                    let key = BitmapKey {
                                        account_id,
                                        collection,
                                        family,
                                        field,
                                        key: word.as_bytes(),
                                    };
                                    if !requested_keys.contains(&key) {
                                        requested_keys.insert(key);
                                        keys.push(key);
                                    }
                                }
                            }

                            // Term already matched on a previous iteration
                            if keys.is_empty() {
                                continue;
                            }

                            Filter::And.apply(
                                &mut text_bitmap,
                                self.get_bitmaps_union(keys)?,
                                &document_ids,
                            );

                            if text_bitmap.as_ref().unwrap().is_empty() {
                                break;
                            }
                        }
                        state.op.apply(&mut state.bm, text_bitmap, &document_ids);
                    }
                }
                Filter::InBitmap { family, field, key } => {
                    state.op.apply(
                        &mut state.bm,
                        self.get_bitmap(BitmapKey {
                            account_id,
                            collection,
                            family,
                            field,
                            key: &key,
                        })?,
                        &document_ids,
                    );
                }
                Filter::DocumentSet(set) => {
                    state.op.apply(&mut state.bm, Some(set), &document_ids);
                }
                op @ (Filter::And | Filter::Or | Filter::Not) => {
                    stack.push(state);
                    state = op.into();
                    continue;
                }
                Filter::End => {
                    if let Some(mut prev_state) = stack.pop() {
                        prev_state
                            .op
                            .apply(&mut prev_state.bm, state.bm, &document_ids);
                        state = prev_state;
                    } else {
                        break;
                    }
                }
            }

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
