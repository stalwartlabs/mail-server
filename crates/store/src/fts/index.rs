/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Display};

use ahash::AHashMap;
use nlp::{
    language::{
        detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
        stemmer::Stemmer,
        Language,
    },
    tokenizers::word::WordTokenizer,
};

use crate::{
    backend::MAX_TOKEN_LENGTH,
    dispatch::DocumentSet,
    write::{
        hash::TokenType, key::DeserializeBigEndian, BatchBuilder, BitmapHash, MaybeDynamicId,
        Operation, ValueClass, ValueOp,
    },
    IterateParams, Serialize, Store, ValueKey, U32_LEN,
};

use super::{postings::Postings, Field};
pub const TERM_INDEX_VERSION: u8 = 1;

#[derive(Debug)]
pub(crate) struct Text<'x, T: Into<u8> + Display + Clone + std::fmt::Debug> {
    pub field: Field<T>,
    pub text: Cow<'x, str>,
    pub typ: Type,
}

#[derive(Debug)]
pub(crate) enum Type {
    Text(Language),
    Tokenize,
    Keyword,
}

#[derive(Debug)]
pub struct FtsDocument<'x, T: Into<u8> + Display + Clone + std::fmt::Debug> {
    pub(crate) parts: Vec<Text<'x, T>>,
    pub(crate) default_language: Language,
    pub(crate) account_id: u32,
    pub(crate) collection: u8,
    pub(crate) document_id: u32,
}

impl<'x, T: Into<u8> + Display + Clone + std::fmt::Debug> FtsDocument<'x, T> {
    pub fn with_default_language(default_language: Language) -> FtsDocument<'x, T> {
        FtsDocument {
            parts: vec![],
            default_language,
            account_id: 0,
            document_id: 0,
            collection: 0,
        }
    }

    pub fn with_account_id(mut self, account_id: u32) -> Self {
        self.account_id = account_id;
        self
    }

    pub fn with_document_id(mut self, document_id: u32) -> Self {
        self.document_id = document_id;
        self
    }

    pub fn with_collection(mut self, collection: impl Into<u8>) -> Self {
        self.collection = collection.into();
        self
    }

    pub fn index(&mut self, field: Field<T>, text: impl Into<Cow<'x, str>>, language: Language) {
        self.parts.push(Text {
            field,
            text: text.into(),
            typ: Type::Text(language),
        });
    }

    pub fn index_tokenized(&mut self, field: Field<T>, text: impl Into<Cow<'x, str>>) {
        self.parts.push(Text {
            field,
            text: text.into(),
            typ: Type::Tokenize,
        });
    }

    pub fn index_keyword(&mut self, field: Field<T>, text: impl Into<Cow<'x, str>>) {
        let text = text.into();
        if !text.is_empty() {
            self.parts.push(Text {
                field,
                text,
                typ: Type::Keyword,
            });
        }
    }
}

impl<T: Into<u8> + Display + Clone + std::fmt::Debug> From<Field<T>> for u8 {
    fn from(value: Field<T>) -> Self {
        match value {
            Field::Body => 0,
            Field::Attachment => 1,
            Field::Keyword => 2,
            Field::Header(value) => 3 + value.into(),
        }
    }
}

impl Store {
    pub async fn fts_index<T: Into<u8> + Display + Clone + std::fmt::Debug>(
        &self,
        document: FtsDocument<'_, T>,
    ) -> trc::Result<()> {
        let mut detect = LanguageDetector::new();
        let mut tokens: AHashMap<BitmapHash, Postings> = AHashMap::new();
        let mut parts = Vec::new();
        let mut position = 0;

        for text in document.parts {
            match text.typ {
                Type::Text(language) => {
                    let language = if language == Language::Unknown {
                        detect.detect(&text.text, MIN_LANGUAGE_SCORE)
                    } else {
                        language
                    };
                    parts.push((text.field, language, text.text));
                }
                Type::Tokenize => {
                    let field = u8::from(text.field);
                    for token in WordTokenizer::new(text.text.as_ref(), MAX_TOKEN_LENGTH) {
                        tokens
                            .entry(BitmapHash::new(token.word.as_ref()))
                            .or_default()
                            .insert(TokenType::word(field), position);
                        position += 1;
                    }
                    position += 10;
                }
                Type::Keyword => {
                    let value = text.text.as_ref();
                    if !value.is_empty() {
                        let field = u8::from(text.field);
                        tokens
                            .entry(BitmapHash::new(value))
                            .or_default()
                            .insert_keyword(TokenType::word(field));
                    }
                }
            }
        }

        let default_language = detect
            .most_frequent_language()
            .unwrap_or(document.default_language);

        for (field, language, text) in parts.into_iter() {
            let language = if language != Language::Unknown {
                language
            } else {
                default_language
            };
            let field: u8 = field.into();

            for token in Stemmer::new(&text, language, MAX_TOKEN_LENGTH) {
                tokens
                    .entry(BitmapHash::new(token.word.as_ref()))
                    .or_default()
                    .insert(TokenType::word(field), position);

                if let Some(stemmed_word) = token.stemmed_word {
                    tokens
                        .entry(BitmapHash::new(stemmed_word.as_ref()))
                        .or_default()
                        .insert_keyword(TokenType::stemmed(field));
                }

                position += 1;
            }

            position += 10;
        }

        if tokens.is_empty() {
            return Ok(());
        }

        // Serialize keys
        let mut keys = Vec::with_capacity(tokens.len());
        for (hash, postings) in tokens.into_iter() {
            keys.push(Operation::Value {
                class: ValueClass::FtsIndex(hash),
                op: ValueOp::Set(postings.serialize().into()),
            });
        }

        // Commit index
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(document.account_id)
            .with_collection(document.collection)
            .update_document(document.document_id);

        for key in keys.into_iter() {
            if batch.ops.len() >= 1000 {
                self.write(batch.build()).await?;
                batch = BatchBuilder::new();
                batch
                    .with_account_id(document.account_id)
                    .with_collection(document.collection)
                    .update_document(document.document_id);
            }
            batch.ops.push(key);
        }

        if !batch.is_empty() {
            self.write(batch.build()).await?;
        }

        Ok(())
    }

    pub async fn fts_remove(
        &self,
        account_id: u32,
        collection: u8,
        document_ids: &impl DocumentSet,
    ) -> trc::Result<()> {
        // Find keys to delete
        let mut delete_keys: AHashMap<u32, Vec<ValueClass<MaybeDynamicId>>> = AHashMap::new();
        self.iterate(
            IterateParams::new(
                ValueKey {
                    account_id,
                    collection,
                    document_id: 0,
                    class: ValueClass::FtsIndex(BitmapHash {
                        hash: [0; 8],
                        len: 1,
                    }),
                },
                ValueKey {
                    account_id: account_id + 1,
                    collection,
                    document_id: 0,
                    class: ValueClass::FtsIndex(BitmapHash {
                        hash: [0; 8],
                        len: 1,
                    }),
                },
            )
            .no_values(),
            |key, _| {
                let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                if document_ids.contains(document_id) {
                    let mut hash = [0u8; 8];
                    let (hash, len) = match key.len() - (U32_LEN * 2) - 1 {
                        9 => {
                            hash[..8].copy_from_slice(&key[U32_LEN..U32_LEN + 8]);
                            (hash, key[key.len() - U32_LEN - 2])
                        }
                        len @ (1..=7) => {
                            hash[..len].copy_from_slice(&key[U32_LEN..U32_LEN + len]);
                            (hash, len as u8)
                        }
                        0 => {
                            // Temporary fix for empty keywords
                            (hash, 0)
                        }
                        invalid => {
                            return Err(trc::Error::corrupted_key(key, None, trc::location!())
                                .ctx(trc::Key::Reason, "Invalid bitmap key length")
                                .ctx(trc::Key::Size, invalid));
                        }
                    };

                    delete_keys
                        .entry(document_id)
                        .or_default()
                        .push(ValueClass::FtsIndex(BitmapHash { hash, len }));
                }

                Ok(true)
            },
        )
        .await?;

        // Remove keys
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(collection);

        for (document_id, keys) in delete_keys {
            batch.update_document(document_id);

            for key in keys {
                if batch.ops.len() >= 1000 {
                    self.write(batch.build()).await?;
                    batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(collection)
                        .update_document(document_id);
                }
                batch.ops.push(Operation::Value {
                    class: key,
                    op: ValueOp::Clear,
                });
            }
        }

        if !batch.is_empty() {
            self.write(batch.build()).await?;
        }

        Ok(())
    }

    pub async fn fts_remove_all(&self, _: u32) -> trc::Result<()> {
        // No-op
        // Term indexes are stored in the same key range as the document

        Ok(())
    }
}
