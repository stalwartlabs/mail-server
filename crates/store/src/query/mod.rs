/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod filter;
pub mod log;
pub mod sort;

use roaring::RoaringBitmap;

use crate::{
    write::{BitmapClass, BitmapHash, TagValue},
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
    InBitmap(BitmapClass<u32>),
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

    pub fn is_in_bitmap(field: impl Into<u8>, value: impl Into<TagValue<u32>>) -> Self {
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

impl BitmapKey<BitmapClass<u32>> {
    pub fn document_ids(account_id: u32, collection: impl Into<u8>) -> Self {
        BitmapKey {
            account_id,
            collection: collection.into(),
            class: BitmapClass::DocumentIds,
            document_id: 0,
        }
    }

    pub fn text_token(
        account_id: u32,
        collection: impl Into<u8>,
        field: impl Into<u8>,
        token: impl AsRef<[u8]>,
    ) -> Self {
        BitmapKey {
            account_id,
            collection: collection.into(),
            class: BitmapClass::Text {
                field: field.into(),
                token: BitmapHash::new(token),
            },
            document_id: 0,
        }
    }

    pub fn tag(
        account_id: u32,
        collection: impl Into<u8>,
        field: impl Into<u8>,
        value: impl Into<TagValue<u32>>,
    ) -> Self {
        BitmapKey {
            account_id,
            collection: collection.into(),
            class: BitmapClass::Tag {
                field: field.into(),
                value: value.into(),
            },
            document_id: 0,
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

    pub fn set_ascending(mut self, ascending: bool) -> Self {
        self.ascending = ascending;
        self
    }

    pub fn set_values(mut self, values: bool) -> Self {
        self.values = values;
        self
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
