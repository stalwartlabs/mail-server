use std::borrow::Cow;

use ahash::AHashSet;

use crate::{
    write::{BatchBuilder, IntoOperations, Operation},
    Serialize, BLOOM_BIGRAM, BLOOM_TRIGRAM, BM_HASH, HASH_EXACT, HASH_STEMMED,
};

use super::{
    bloom::{hash_token, BloomFilter},
    lang::{LanguageDetector, MIN_LANGUAGE_SCORE},
    ngram::ToNgrams,
    stemmer::Stemmer,
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
                unique_words.insert((token.word.to_string(), HASH_EXACT));
                if let Some(stemmed_word) = token.stemmed_word {
                    unique_words.insert((stemmed_word.into_owned(), HASH_STEMMED));
                }
                phrase_words.push(token.word);
            }

            for (word, family) in unique_words {
                batch.ops.push(Operation::Bitmap {
                    family: BM_HASH | family | (word.len() & MAX_TOKEN_MASK) as u8,
                    field: part.field,
                    key: hash_token(&word),
                    set: true,
                });
            }

            if phrase_words.len() > 1 {
                batch.ops.push(Operation::Value {
                    field: part.field,
                    family: BLOOM_BIGRAM,
                    set: BloomFilter::to_ngrams(&phrase_words, 2).serialize().into(),
                });
                if phrase_words.len() > 2 {
                    batch.ops.push(Operation::Value {
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
