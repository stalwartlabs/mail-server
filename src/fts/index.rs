use std::collections::HashSet;

use ahash::AHashSet;

use crate::{
    write::{BatchBuilder, IntoOperations, Operation, Tokenize},
    Error, Serialize, BM_TERM, TERM_EXACT, TERM_STEMMED,
};

use super::{
    lang::{LanguageDetector, MIN_LANGUAGE_SCORE},
    stemmer::Stemmer,
    term_index::{TermIndexBuilder, TokenIndex},
    Language,
};

pub const MAX_TOKEN_LENGTH: usize = 25;

struct Text<'x> {
    field: u8,
    text: &'x str,
    language: Language,
    part_id: u32,
}

pub struct IndexBuilder<'x> {
    parts: Vec<Text<'x>>,
    detect: LanguageDetector,
    default_language: Language,
}

impl<'x> IndexBuilder<'x> {
    pub fn with_default_language(default_language: Language) -> IndexBuilder<'x> {
        IndexBuilder {
            parts: vec![],
            detect: LanguageDetector::new(),
            default_language,
        }
    }

    pub fn index(
        &mut self,
        field: impl Into<u8>,
        text: &'x str,
        mut language: Language,
        part_id: u32,
    ) {
        if language == Language::Unknown {
            language = self.detect.detect(text, MIN_LANGUAGE_SCORE);
        }
        self.parts.push(Text {
            field: field.into(),
            text,
            language,
            part_id,
        });
    }
}

impl<'x> IntoOperations for IndexBuilder<'x> {
    fn build(self, batch: &mut BatchBuilder) -> crate::Result<()> {
        let default_language = self
            .detect
            .most_frequent_language()
            .unwrap_or(self.default_language);
        let mut term_index = TermIndexBuilder::new();
        let mut words = HashSet::new();

        for part in &self.parts {
            let language = if part.language != Language::Unknown {
                part.language
            } else {
                default_language
            };

            let mut terms = Vec::new();

            for token in Stemmer::new(part.text, language, MAX_TOKEN_LENGTH) {
                words.insert((token.word.as_bytes().to_vec(), part.field, true));

                if let Some(stemmed_word) = token.stemmed_word.as_ref() {
                    words.insert((stemmed_word.as_bytes().to_vec(), part.field, false));
                }

                terms.push(term_index.add_stemmed_token(token));
            }

            if !terms.is_empty() {
                term_index.add_terms(part.field, part.part_id, terms);
            }
        }

        for (key, field, is_exact) in words {
            batch.ops.push(Operation::Bitmap {
                family: BM_TERM | if is_exact { TERM_EXACT } else { TERM_STEMMED },
                field,
                key,
                set: true,
            });
        }

        if !term_index.is_empty() {
            batch.ops.push(Operation::Value {
                field: u8::MAX,
                set: term_index.serialize().into(),
            });
        }

        Ok(())
    }
}

impl IntoOperations for TokenIndex {
    fn build(self, batch: &mut BatchBuilder) -> crate::Result<()> {
        let mut tokens = AHashSet::new();

        for term in self.terms {
            for (term_ids, is_exact) in [(term.exact_terms, true), (term.stemmed_terms, false)] {
                for term_id in term_ids {
                    tokens.insert((
                        term.field_id,
                        is_exact,
                        self.tokens
                            .get(term_id as usize)
                            .ok_or_else(|| {
                                Error::InternalError("Corrupted term index.".to_string())
                            })?
                            .as_bytes()
                            .to_vec(),
                    ));
                }
            }
        }

        for (field, is_exact, key) in tokens {
            batch.ops.push(Operation::Bitmap {
                family: BM_TERM | if is_exact { TERM_EXACT } else { TERM_STEMMED },
                field,
                key,
                set: false,
            });
        }

        batch.ops.push(Operation::Value {
            field: u8::MAX,
            set: None,
        });

        Ok(())
    }
}

impl Tokenize for TermIndexBuilder {
    fn tokenize(&self) -> HashSet<Vec<u8>> {
        unreachable!()
    }
}
