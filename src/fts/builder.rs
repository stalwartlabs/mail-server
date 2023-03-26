use std::borrow::Cow;

use ahash::AHashSet;

use crate::{
    write::{BatchBuilder, IntoOperations, Operation},
    Serialize, BLOOM_BIGRAM, BLOOM_STEMMED, BLOOM_TRIGRAM, BM_BLOOM,
};

use super::{
    bloom::{BloomFilter, BloomHash},
    lang::{LanguageDetector, MIN_LANGUAGE_SCORE},
    ngram::ToNgrams,
    stemmer::Stemmer,
    Language,
};

pub const MAX_TOKEN_LENGTH: usize = 50;

struct Text<'x> {
    field: u8,
    text: Cow<'x, str>,
    language: Language,
}

pub struct FtsIndexBuilder<'x> {
    parts: Vec<Text<'x>>,
    detect: LanguageDetector,
    default_language: Language,
}

impl<'x> FtsIndexBuilder<'x> {
    pub fn with_default_language(default_language: Language) -> FtsIndexBuilder<'x> {
        FtsIndexBuilder {
            parts: vec![],
            detect: LanguageDetector::new(),
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
}

impl<'x> IntoOperations for FtsIndexBuilder<'x> {
    fn build(self, batch: &mut BatchBuilder) -> crate::Result<()> {
        let default_language = self
            .detect
            .most_frequent_language()
            .unwrap_or(self.default_language);

        for part in &self.parts {
            let language = if part.language != Language::Unknown {
                part.language
            } else {
                default_language
            };
            let mut unique_words = AHashSet::new();
            let mut phrase_words = Vec::new();

            for token in Stemmer::new(&part.text, language, MAX_TOKEN_LENGTH).collect::<Vec<_>>() {
                unique_words.insert(token.word.to_string());
                if let Some(stemmed_word) = token.stemmed_word.as_ref() {
                    unique_words.insert(format!("{}_", stemmed_word));
                }
                phrase_words.push(token.word);
            }

            let mut bloom_stemmed = BloomFilter::new(unique_words.len());
            for word in unique_words {
                let hash = BloomHash::from(word);
                bloom_stemmed.insert(&hash);
                //for h in [0, 1] {
                batch.ops.push(Operation::Bitmap {
                    family: BM_BLOOM,
                    field: part.field,
                    key: hash.as_high_rank_hash(0).serialize(),
                    set: true,
                });
                //}
            }

            batch.ops.push(Operation::Bloom {
                field: part.field,
                family: BLOOM_STEMMED,
                set: bloom_stemmed.serialize().into(),
            });

            if phrase_words.len() > 1 {
                batch.ops.push(Operation::Bloom {
                    field: part.field,
                    family: BLOOM_BIGRAM,
                    set: BloomFilter::to_ngrams(&phrase_words, 2).serialize().into(),
                });
                if phrase_words.len() > 2 {
                    batch.ops.push(Operation::Bloom {
                        field: part.field,
                        family: BLOOM_TRIGRAM,
                        set: BloomFilter::to_ngrams(&phrase_words, 3).serialize().into(),
                    });
                }
            }
        }

        Ok(())
    }
}

/*
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
*/
