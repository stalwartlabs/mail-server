use std::{borrow::Cow, collections::HashSet};

use ahash::AHashSet;
use utils::map::vec_map::VecMap;

use crate::{
    write::{BatchBuilder, IntoOperations, Operation},
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

        for (part_id, part) in self.parts.iter().enumerate() {
            let language = if part.language != Language::Unknown {
                part.language
            } else {
                default_language
            };
            let mut unique_words = AHashSet::new();
            let mut terms = Vec::new();

            for token in Stemmer::new(&part.text, language, MAX_TOKEN_LENGTH).collect::<Vec<_>>() {
                unique_words.insert((token.word.to_string(), HASH_EXACT));
                if let Some(stemmed_word) = &token.stemmed_word {
                    unique_words.insert((stemmed_word.to_string(), HASH_STEMMED));
                }
                terms.push(term_index.add_stemmed_token(token));
            }

            if !terms.is_empty() {
                term_index.add_terms(part.field, part_id as u32, terms);
            }

            for (word, family) in unique_words {
                batch
                    .ops
                    .push(Operation::hash(&word, family, part.field, true));
            }
        }

        for (field, tokens) in self.tokens {
            let mut terms = Vec::with_capacity(tokens.len());
            for token in tokens {
                batch
                    .ops
                    .push(Operation::hash(&token, HASH_EXACT, field, true));
                terms.push(term_index.add_token(Token {
                    word: token.into(),
                    offset: 0,
                    len: 0,
                }));
            }
            term_index.add_terms(field, 0, terms);
        }

        batch.ops.push(Operation::Value {
            field: u8::MAX,
            family: u8::MAX,
            set: term_index.serialize().into(),
        });
    }
}

impl IntoOperations for TokenIndex {
    fn build(self, batch: &mut BatchBuilder) {
        for term in self.terms {
            for (term_ids, is_exact) in [(term.exact_terms, true), (term.stemmed_terms, false)] {
                for term_id in term_ids {
                    if let Some(word) = self.tokens.get(term_id as usize) {
                        batch.ops.push(Operation::hash(
                            word,
                            if is_exact { HASH_EXACT } else { HASH_STEMMED },
                            term.field_id,
                            false,
                        ));
                    }
                }
            }
        }

        batch.ops.push(Operation::Value {
            field: u8::MAX,
            family: u8::MAX,
            set: None,
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
