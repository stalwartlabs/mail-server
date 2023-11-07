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

use std::{borrow::Cow, collections::HashSet, fmt::Display};

use ahash::AHashSet;
use nlp::{
    language::{
        detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
        stemmer::Stemmer,
        Language,
    },
    tokenizers::{space::SpaceTokenizer, Token},
};
use utils::map::vec_map::VecMap;

use crate::{
    query::RawValue,
    write::{BatchBuilder, IntoOperations, Operation, ValueClass},
    Serialize, HASH_EXACT, HASH_STEMMED,
};

use super::term_index::{TermIndexBuilder, TokenIndex};

pub const MAX_TOKEN_LENGTH: usize = (u8::MAX >> 2) as usize;
pub const MAX_TOKEN_MASK: usize = MAX_TOKEN_LENGTH - 1;

struct Text<'x, T: Into<u8> + Display> {
    field: T,
    text: Cow<'x, str>,
    language: Type,
}

enum Type {
    Stem(Language),
    Tokenize,
    Static,
}

pub struct FtsIndexBuilder<'x, T: Into<u8> + Display> {
    parts: Vec<Text<'x, T>>,
    default_language: Language,
}

impl<'x, T: Into<u8> + Display> FtsIndexBuilder<'x, T> {
    pub fn with_default_language(default_language: Language) -> FtsIndexBuilder<'x, T> {
        FtsIndexBuilder {
            parts: vec![],
            default_language,
        }
    }

    pub fn index(&mut self, field: T, text: impl Into<Cow<'x, str>>, language: Language) {
        self.parts.push(Text {
            field,
            text: text.into(),
            language: Type::Stem(language),
        });
    }

    pub fn index_raw(&mut self, field: T, text: impl Into<Cow<'x, str>>) {
        self.parts.push(Text {
            field,
            text: text.into(),
            language: Type::Tokenize,
        });
    }

    pub fn index_raw_token(&mut self, field: T, text: impl Into<Cow<'x, str>>) {
        self.parts.push(Text {
            field,
            text: text.into(),
            language: Type::Static,
        });
    }
}

impl<'x, T: Into<u8> + Display> IntoOperations for FtsIndexBuilder<'x, T> {
    fn build(self, batch: &mut BatchBuilder) {
        let mut detect = LanguageDetector::new();
        let mut tokens: VecMap<u8, AHashSet<String>> = VecMap::new();
        let mut parts = Vec::new();

        for text in self.parts {
            match text.language {
                Type::Stem(language) => {
                    let language = if language == Language::Unknown {
                        detect.detect(&text.text, MIN_LANGUAGE_SCORE)
                    } else {
                        language
                    };
                    parts.push((text.field, language, text.text));
                }
                Type::Tokenize => {
                    let tokens = tokens.get_mut_or_insert(text.field.into());
                    for token in SpaceTokenizer::new(text.text.as_ref(), MAX_TOKEN_LENGTH) {
                        tokens.insert(token);
                    }
                }
                Type::Static => {
                    tokens
                        .get_mut_or_insert(text.field.into())
                        .insert(text.text.into_owned());
                }
            }
        }

        let default_language = detect
            .most_frequent_language()
            .unwrap_or(self.default_language);
        let mut term_index = TermIndexBuilder::new();
        let mut ops = AHashSet::new();

        for (part_id, (field, language, text)) in parts.into_iter().enumerate() {
            let language = if language != Language::Unknown {
                language
            } else {
                default_language
            };
            let mut terms = Vec::new();
            let field: u8 = field.into();

            for token in Stemmer::new(&text, language, MAX_TOKEN_LENGTH).collect::<Vec<_>>() {
                ops.insert(Operation::hash(&token.word, HASH_EXACT, field, true));
                if let Some(stemmed_word) = &token.stemmed_word {
                    ops.insert(Operation::hash(stemmed_word, HASH_STEMMED, field, true));
                }
                terms.push(term_index.add_stemmed_token(token));
            }

            if !terms.is_empty() {
                term_index.add_terms(field, part_id as u32, terms);
            }
        }

        for (field, tokens) in tokens {
            let mut terms = Vec::with_capacity(tokens.len());
            for token in tokens {
                ops.insert(Operation::hash(&token, HASH_EXACT, field, true));
                terms.push(term_index.add_token(Token {
                    word: token.into(),
                    from: 0,
                    to: 0,
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
