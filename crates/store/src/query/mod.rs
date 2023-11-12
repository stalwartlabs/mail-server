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

pub mod acl;
pub mod filter;
pub mod log;
pub mod sort;

use roaring::RoaringBitmap;

use crate::{
    write::{BitmapClass, TagValue},
    BitmapKey, IterateParams, Key, Serialize,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    LowerThan,
    LowerEqualThan,
    GreaterThan,
    GreaterEqualThan,
    Equal,
}

#[derive(Debug)]
pub enum Filter {
    MatchValue {
        field: u8,
        op: Operator,
        value: Vec<u8>,
    },
    HasText {
        field: u8,
        text: String,
        tokenize: bool,
    },
    InBitmap(BitmapClass),
    DocumentSet(RoaringBitmap),
    And,
    Or,
    Not,
    End,
}

#[derive(Debug)]
pub enum Comparator {
    Field { field: u8, ascending: bool },
    DocumentSet { set: RoaringBitmap, ascending: bool },
}

#[derive(Debug)]
pub struct ResultSet {
    pub account_id: u32,
    pub collection: u8,
    pub results: RoaringBitmap,
}

pub struct SortedResultSet {
    pub position: i32,
    pub ids: Vec<u64>,
    pub found_anchor: bool,
}

impl ResultSet {
    pub fn new(account_id: u32, collection: impl Into<u8>, results: RoaringBitmap) -> Self {
        ResultSet {
            account_id,
            collection: collection.into(),
            results,
        }
    }

    pub fn apply_mask(&mut self, mask: RoaringBitmap) {
        self.results &= mask;
    }
}

impl Filter {
    pub fn cond(field: impl Into<u8>, op: Operator, value: impl Serialize) -> Self {
        Filter::MatchValue {
            field: field.into(),
            op,
            value: value.serialize(),
        }
    }

    pub fn eq(field: impl Into<u8>, value: impl Serialize) -> Self {
        Filter::MatchValue {
            field: field.into(),
            op: Operator::Equal,
            value: value.serialize(),
        }
    }

    pub fn lt(field: impl Into<u8>, value: impl Serialize) -> Self {
        Filter::MatchValue {
            field: field.into(),
            op: Operator::LowerThan,
            value: value.serialize(),
        }
    }

    pub fn le(field: impl Into<u8>, value: impl Serialize) -> Self {
        Filter::MatchValue {
            field: field.into(),
            op: Operator::LowerEqualThan,
            value: value.serialize(),
        }
    }

    pub fn gt(field: impl Into<u8>, value: impl Serialize) -> Self {
        Filter::MatchValue {
            field: field.into(),
            op: Operator::GreaterThan,
            value: value.serialize(),
        }
    }

    pub fn ge(field: impl Into<u8>, value: impl Serialize) -> Self {
        Filter::MatchValue {
            field: field.into(),
            op: Operator::GreaterEqualThan,
            value: value.serialize(),
        }
    }

    /*pub fn has_text_detect(
        field: impl Into<u8>,
        text: impl Into<String>,
        default_language: Language,
    ) -> Self {
        let (text, language) = Language::detect(text.into(), default_language);
        Self::has_text(field, text, language)
    }

    pub fn has_text(field: impl Into<u8>, text: impl Into<String>, language: Language) -> Self {
        let text = text.into();
        let op = if !matches!(language, Language::None) {
            if (text.starts_with('"') && text.ends_with('"'))
                || (text.starts_with('\'') && text.ends_with('\''))
            {
                TextMatch::Exact(language)
            } else {
                TextMatch::Stemmed(language)
            }
        } else {
            TextMatch::Tokenized
        };

        Filter::HasText {
            field: field.into(),
            text,
            op,
        }
    }

    pub fn has_raw_text(field: impl Into<u8>, text: impl Into<String>) -> Self {
        Filter::HasText {
            field: field.into(),
            text: text.into(),
            op: TextMatch::Raw,
        }
    }

    pub fn has_english_text(field: impl Into<u8>, text: impl Into<String>) -> Self {
        Self::has_text(field, text, Language::English)
    }*/

    pub fn has_text(field: impl Into<u8>, text: impl Into<String>) -> Self {
        Filter::HasText {
            field: field.into(),
            text: text.into(),
            tokenize: true,
        }
    }

    pub fn has_text_token(field: impl Into<u8>, text: impl Into<String>) -> Self {
        Filter::HasText {
            field: field.into(),
            text: text.into(),
            tokenize: true,
        }
    }

    pub fn is_in_bitmap(field: impl Into<u8>, value: impl Into<TagValue>) -> Self {
        Self::InBitmap(BitmapClass::Tag {
            field: field.into(),
            value: value.into(),
        })
    }

    pub fn is_in_set(set: RoaringBitmap) -> Self {
        Filter::DocumentSet(set)
    }
}

impl Comparator {
    pub fn field(field: impl Into<u8>, ascending: bool) -> Self {
        Self::Field {
            field: field.into(),
            ascending,
        }
    }

    pub fn set(set: RoaringBitmap, ascending: bool) -> Self {
        Self::DocumentSet { set, ascending }
    }

    pub fn ascending(field: impl Into<u8>) -> Self {
        Self::Field {
            field: field.into(),
            ascending: true,
        }
    }

    pub fn descending(field: impl Into<u8>) -> Self {
        Self::Field {
            field: field.into(),
            ascending: false,
        }
    }
}

impl BitmapKey<BitmapClass> {
    pub fn document_ids(account_id: u32, collection: impl Into<u8>) -> Self {
        BitmapKey {
            account_id,
            collection: collection.into(),
            class: BitmapClass::DocumentIds,
            block_num: 0,
        }
    }

    pub fn text_token(
        account_id: u32,
        collection: impl Into<u8>,
        field: impl Into<u8>,
        token: impl Into<Vec<u8>>,
    ) -> Self {
        BitmapKey {
            account_id,
            collection: collection.into(),
            class: BitmapClass::Text {
                field: field.into(),
                token: token.into(),
            },
            block_num: 0,
        }
    }

    pub fn tag(
        account_id: u32,
        collection: impl Into<u8>,
        field: impl Into<u8>,
        value: impl Into<TagValue>,
    ) -> Self {
        BitmapKey {
            account_id,
            collection: collection.into(),
            class: BitmapClass::Tag {
                field: field.into(),
                value: value.into(),
            },
            block_num: 0,
        }
    }
}

impl<T: Key> IterateParams<T> {
    pub fn new(begin: T, end: T) -> Self {
        IterateParams {
            begin,
            end,
            first: false,
            ascending: true,
            values: true,
        }
    }

    pub fn ascending(mut self) -> Self {
        self.ascending = true;
        self
    }

    pub fn descending(mut self) -> Self {
        self.ascending = false;
        self
    }

    pub fn only_first(mut self) -> Self {
        self.first = true;
        self
    }

    pub fn no_values(mut self) -> Self {
        self.values = false;
        self
    }
}

/*
#[derive(Debug)]
pub struct RawValue<T: Deserialize> {
    pub raw: Vec<u8>,
    pub inner: T,
}

impl<T: Deserialize> Deserialize for RawValue<T> {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        Ok(RawValue {
            inner: T::deserialize(bytes)?,
            raw: bytes.to_vec(),
        })
    }
}
*/
