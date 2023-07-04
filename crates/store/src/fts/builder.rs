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

use std::{borrow::Cow, collections::HashSet};

use ahash::AHashSet;
use utils::map::vec_map::VecMap;

use crate::{
    query::RawValue,
    write::{BatchBuilder, IntoOperations, Operation, ValueClass},
    Serialize, HASH_EXACT, HASH_STEMMED,
};

use super::{
    lang::{LanguageDetector, MIN_LANGUAGE_SCORE},
    stemmer::Stemmer,
    term_index::{TermIndexBuilder, TokenIndex},
    tokenizers::{space::SpaceTokenizer, Token},
    Language,
};

pub const MAX_TOKEN_LENGTH: usize = (u8::MAX >> 2) as usize;
pub const MAX_TOKEN_MASK: usize = MAX_TOKEN_LENGTH - 1;

struct Text<'x> {
    field: u8,
    text: Cow<'x, str>,
    language: Language,
}

pub struct FtsIndexBuilder<'x> {
    parts: Vec<Text<'x>>,
    tokens: VecMap<u8, AHashSet<String>>,
    detect: LanguageDetector,
    default_language: Language,
}

impl<'x> FtsIndexBuilder<'x> {
    pub fn with_default_language(default_language: Language) -> FtsIndexBuilder<'x> {
        FtsIndexBuilder {
            parts: vec![],
            detect: LanguageDetector::new(),
            tokens: VecMap::new(),
            default_language,
        }
    }

    pub fn index(
        &mut self,
        field: impl Into<u8>,
        text: impl Into<Cow<'x, str>>,
        mut language: Language,
    ) {
        let text = text.into();
        if language == Language::Unknown {
            language = self.detect.detect(&text, MIN_LANGUAGE_SCORE);
        }
        self.parts.push(Text {
            field: field.into(),
            text,
            language,
        });
    }

    pub fn index_raw(&mut self, field: impl Into<u8>, text: &str) {
        let tokens = self.tokens.get_mut_or_insert(field.into());
        for token in SpaceTokenizer::new(text, MAX_TOKEN_LENGTH) {
            tokens.insert(token);
        }
    }

    pub fn index_raw_token(&mut self, field: impl Into<u8>, token: impl Into<String>) {
        self.tokens
            .get_mut_or_insert(field.into())
            .insert(token.into());
    }
}

impl<'x> IntoOperations for FtsIndexBuilder<'x> {
    fn build(self, batch: &mut BatchBuilder) {
        let default_language = self
            .detect
            .most_frequent_language()
            .unwrap_or(self.default_language);
        let mut term_index = TermIndexBuilder::new();
        let mut ops = AHashSet::new();

        for (part_id, part) in self.parts.iter().enumerate() {
            let language = if part.language != Language::Unknown {
                part.language
            } else {
                default_language
            };
            let mut terms = Vec::new();

            for token in Stemmer::new(&part.text, language, MAX_TOKEN_LENGTH).collect::<Vec<_>>() {
                ops.insert(Operation::hash(&token.word, HASH_EXACT, part.field, true));
                if let Some(stemmed_word) = &token.stemmed_word {
                    ops.insert(Operation::hash(
                        stemmed_word,
                        HASH_STEMMED,
                        part.field,
                        true,
                    ));
                }
                terms.push(term_index.add_stemmed_token(token));
            }

            if !terms.is_empty() {
                term_index.add_terms(part.field, part_id as u32, terms);
            }
        }

        for (field, tokens) in self.tokens {
            let mut terms = Vec::with_capacity(tokens.len());
            for token in tokens {
                ops.insert(Operation::hash(&token, HASH_EXACT, field, true));
                terms.push(term_index.add_token(Token {
                    word: token.into(),
                    offset: 0,
                    len: 0,
                }));
            }
            term_index.add_terms(field, 0, terms);
        }

        for op in ops {
            batch.ops.push(op);
        }

        batch.ops.push(Operation::Value {
            class: ValueClass::Property {
                field: u8::MAX,
                family: u8::MAX,
            },
            set: term_index.serialize().into(),
        });
    }
}

impl TokenIndex {
    fn build_index(self, batch: &mut BatchBuilder, set: bool) {
        let mut ops = AHashSet::with_capacity(self.tokens.len() * 2);
        for term in self.terms {
            for (term_ids, is_exact) in [(term.exact_terms, true), (term.stemmed_terms, false)] {
                for term_id in term_ids {
                    if let Some(word) = self.tokens.get(term_id as usize) {
                        ops.insert(Operation::hash(
                            word,
                            if is_exact { HASH_EXACT } else { HASH_STEMMED },
                            term.field_id,
                            set,
                        ));
                    }
                }
            }
        }
        for op in ops {
            batch.ops.push(op);
        }
    }
}

impl IntoOperations for TokenIndex {
    fn build(self, batch: &mut BatchBuilder) {
        self.build_index(batch, false);
        batch.ops.push(Operation::Value {
            class: ValueClass::Property {
                field: u8::MAX,
                family: u8::MAX,
            },
            set: None,
        });
    }
}

impl IntoOperations for RawValue<TokenIndex> {
    fn build(self, batch: &mut BatchBuilder) {
        self.inner.build_index(batch, true);
        batch.ops.push(Operation::Value {
            class: ValueClass::Property {
                field: u8::MAX,
                family: u8::MAX,
            },
            set: self.raw.into(),
        });
    }
}

pub trait ToTokens {
    fn to_tokens(&self) -> HashSet<String>;
}

impl ToTokens for &str {
    fn to_tokens(&self) -> HashSet<String> {
        let mut tokens = HashSet::new();
        for token in SpaceTokenizer::new(self, MAX_TOKEN_LENGTH) {
            tokens.insert(token);
        }
        tokens
    }
}

impl ToTokens for &String {
    fn to_tokens(&self) -> HashSet<String> {
        self.as_str().to_tokens()
    }
}
