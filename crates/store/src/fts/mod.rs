/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use nlp::language::Language;

pub mod index;
pub mod postings;
pub mod query;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Field<T: Into<u8> + Display + Clone + std::fmt::Debug> {
    Header(T),
    Body,
    Attachment,
    Keyword,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FtsFilter<T: Into<u8> + Display + Clone + std::fmt::Debug> {
    Exact {
        field: Field<T>,
        text: String,
        language: Language,
    },
    Contains {
        field: Field<T>,
        text: String,
        language: Language,
    },
    Keyword {
        field: Field<T>,
        text: String,
    },
    And,
    Or,
    Not,
    End,
}

impl<T: Into<u8> + Display + Clone + std::fmt::Debug> FtsFilter<T> {
    pub fn has_text_detect(
        field: Field<T>,
        text: impl Into<String>,
        default_language: Language,
    ) -> Self {
        let (text, language) = Language::detect(text.into(), default_language);
        Self::has_text(field, text, language)
    }

    pub fn has_text(field: Field<T>, text: impl Into<String>, language: Language) -> Self {
        let text = text.into();
        let (is_exact, text) = if let Some(text) = text
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .or_else(|| text.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')))
        {
            (true, text.to_string())
        } else {
            (false, text)
        };

        if !matches!(language, Language::None) && is_exact {
            FtsFilter::Exact {
                field,
                text: text.to_string(),
                language,
            }
        } else {
            FtsFilter::Contains {
                field,
                text,
                language,
            }
        }
    }

    pub fn has_keyword(field: Field<T>, text: impl Into<String>) -> Self {
        FtsFilter::Keyword {
            field,
            text: text.into(),
        }
    }

    pub fn has_english_text(field: Field<T>, text: impl Into<String>) -> Self {
        Self::has_text(field, text, Language::English)
    }
}

#[derive(Clone, Copy)]
pub enum FilterType {
    And,
    Or,
    Not,
    End,
    Store,
    Fts,
}

pub enum FilterGroup<T: FilterItem> {
    Fts(Vec<T>),
    Store(T),
}

pub trait FilterItem: Clone {
    fn filter_type(&self) -> FilterType;
}

pub trait IntoFilterGroup<T: FilterItem + From<FilterType>> {
    fn into_filter_group(self) -> Vec<FilterGroup<T>>;
}

impl<T: FilterItem + From<FilterType>> IntoFilterGroup<T> for Vec<T> {
    fn into_filter_group(self) -> Vec<FilterGroup<T>> {
        let mut filter = Vec::with_capacity(self.len());
        let mut iter = self.into_iter();
        let mut logical_op = None;

        while let Some(item) = iter.next() {
            if matches!(item.filter_type(), FilterType::Fts) {
                let mut store_item = None;
                let mut depth = 0;
                let mut fts = Vec::with_capacity(5);

                // Add the logical operator if there is one
                let in_logical_op = if let Some(op) = logical_op.take() {
                    fts.push(op);
                    true
                } else {
                    false
                };
                fts.push(item);

                for item in iter.by_ref() {
                    match item.filter_type() {
                        FilterType::And | FilterType::Or | FilterType::Not => {
                            depth += 1;
                            fts.push(item);
                        }
                        FilterType::End if depth > 0 => {
                            depth -= 1;
                            fts.push(item);
                        }
                        FilterType::Fts => {
                            fts.push(item);
                        }
                        _ => {
                            store_item = Some(item);
                            break;
                        }
                    }
                }

                if in_logical_op {
                    fts.push(T::from(FilterType::End));
                }

                if depth > 0 {
                    let mut store = Vec::with_capacity(depth * 2);
                    while depth > 0 {
                        let item = fts.pop().unwrap();
                        if matches!(
                            item.filter_type(),
                            FilterType::And | FilterType::Or | FilterType::Not
                        ) {
                            depth -= 1;
                        }
                        store.push(FilterGroup::Store(item));
                    }

                    filter.push(FilterGroup::Fts(fts));
                    filter.extend(store);
                } else {
                    filter.push(FilterGroup::Fts(fts));
                }

                if let Some(item) = store_item {
                    filter.push(FilterGroup::Store(item));
                }
            } else {
                match item.filter_type() {
                    FilterType::And | FilterType::Or => {
                        logical_op = Some(item.clone());
                    }
                    FilterType::Not => {
                        logical_op = Some(T::from(FilterType::And));
                    }
                    _ => {}
                }
                filter.push(FilterGroup::Store(item));
            }
        }

        filter
    }
}
