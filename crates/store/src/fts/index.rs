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

use std::{borrow::Cow, collections::BTreeSet, fmt::Display};

use ahash::{AHashMap, AHashSet};
use nlp::{
    language::{
        detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
        stemmer::Stemmer,
        Language,
    },
    tokenizers::word::WordTokenizer,
};
use utils::codec::leb128::Leb128Reader;

use crate::{
    backend::MAX_TOKEN_LENGTH,
    write::{
        hash::TokenType, key::KeySerializer, BatchBuilder, BitmapClass, BitmapHash, Operation,
        ValueClass,
    },
    Deserialize, Error, Store, ValueKey, U64_LEN,
};

use super::Field;

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
        self.parts.push(Text {
            field,
            text: text.into(),
            typ: Type::Keyword,
        });
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
    ) -> crate::Result<()> {
        let mut detect = LanguageDetector::new();
        let mut tokens: AHashMap<BitmapHash, AHashSet<u8>> = AHashMap::new();
        let mut parts = Vec::new();

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
                            .insert(TokenType::word(field));
                    }
                }
                Type::Keyword => {
                    let field = u8::from(text.field);
                    tokens
                        .entry(BitmapHash::new(text.text.as_ref()))
                        .or_default()
                        .insert(TokenType::word(field));
                }
            }
        }

        let default_language = detect
            .most_frequent_language()
            .unwrap_or(document.default_language);
        let mut bigrams = BTreeSet::new();

        for (field, language, text) in parts.into_iter() {
            let language = if language != Language::Unknown {
                language
            } else {
                default_language
            };
            let field: u8 = field.into();

            let mut last_token = Cow::Borrowed("");
            for token in Stemmer::new(&text, language, MAX_TOKEN_LENGTH) {
                if !last_token.is_empty() {
                    bigrams.insert(BitmapHash::new(&format!("{} {}", last_token, token.word)).hash);
                }

                tokens
                    .entry(BitmapHash::new(token.word.as_ref()))
                    .or_default()
                    .insert(TokenType::word(field));

                if let Some(stemmed_word) = token.stemmed_word {
                    tokens
                        .entry(BitmapHash::new(stemmed_word.as_ref()))
                        .or_default()
                        .insert(TokenType::stemmed(field));
                }

                last_token = token.word;
            }
        }

        if tokens.is_empty() {
            return Ok(());
        }

        // Serialize tokens
        let mut serializer = KeySerializer::new(tokens.len() * U64_LEN * 2);
        let mut keys = Vec::with_capacity(tokens.len());

        // Write bigrams
        serializer = serializer.write_leb128(bigrams.len());
        for bigram in bigrams {
            serializer = serializer.write(bigram.as_slice());
        }

        // Write index keys
        for (hash, fields) in tokens.into_iter() {
            serializer = serializer
                .write(hash.hash.as_slice())
                .write(hash.len)
                .write(fields.len() as u8);
            for field in fields.into_iter() {
                serializer = serializer.write(field);
                keys.push(Operation::Bitmap {
                    class: BitmapClass::Text { field, token: hash },
                    set: true,
                });
            }
        }

        // Write term index
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(document.account_id)
            .with_collection(document.collection)
            .update_document(document.document_id)
            .set(
                ValueClass::TermIndex,
                lz4_flex::compress_prepend_size(&serializer.finalize()),
            );
        self.write(batch.build()).await?;
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
        document_id: u32,
    ) -> crate::Result<bool> {
        // Obtain term index
        let term_index = if let Some(term_index) = self
            .get_value::<TermIndex>(ValueKey {
                account_id,
                collection,
                document_id,
                class: ValueClass::TermIndex,
            })
            .await?
        {
            term_index
        } else {
            return Ok(false);
        };

        // Remove keys
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(collection)
            .update_document(document_id);

        for key in term_index.ops.into_iter() {
            if batch.ops.len() >= 1000 {
                self.write(batch.build()).await?;
                batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(collection)
                    .update_document(document_id);
            }
            batch.ops.push(key);
        }

        if !batch.is_empty() {
            self.write(batch.build()).await?;
        }

        // Remove term index
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(collection)
            .update_document(document_id)
            .clear(ValueClass::TermIndex);

        self.write(batch.build()).await?;

        Ok(true)
    }

    pub async fn fts_remove_all(&self, _: u32) -> crate::Result<()> {
        // No-op
        // Term indexes are stored in the same key range as the document

        Ok(())
    }
}

struct TermIndex {
    ops: Vec<Operation>,
}

impl Deserialize for TermIndex {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        let bytes = lz4_flex::decompress_size_prepended(bytes)
            .map_err(|_| Error::InternalError("Failed to decompress term index".to_string()))?;
        let mut ops = Vec::new();

        // Skip bigrams
        let (num_items, pos) =
            bytes
                .as_slice()
                .read_leb128::<usize>()
                .ok_or(Error::InternalError(
                    "Failed to read term index marker".to_string(),
                ))?;

        let mut bytes = bytes
            .get(pos + (num_items * 8)..)
            .unwrap_or_default()
            .iter()
            .peekable();

        while bytes.peek().is_some() {
            let mut hash = BitmapHash {
                hash: [0; 8],
                len: 0,
            };

            for byte in hash.hash.iter_mut() {
                *byte = *bytes.next().ok_or(Error::InternalError(
                    "Unexpected EOF reading term index".to_string(),
                ))?;
            }

            hash.len = *bytes.next().ok_or(Error::InternalError(
                "Unexpected EOF reading term index".to_string(),
            ))?;
            let num_fields = *bytes.next().ok_or(Error::InternalError(
                "Unexpected EOF reading term index".to_string(),
            ))?;
            for _ in 0..num_fields {
                let field = *bytes.next().ok_or(Error::InternalError(
                    "Unexpected EOF reading term index".to_string(),
                ))?;
                ops.push(Operation::Bitmap {
                    class: BitmapClass::Text { field, token: hash },
                    set: false,
                });
            }
        }

        Ok(Self { ops })
    }
}
