/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod chinese;
pub mod japanese;
pub mod osb;
pub mod space;
pub mod types;
pub mod word;

use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token<T> {
    pub word: T,
    pub from: usize,
    pub to: usize,
}

pub trait InnerToken<'x>: Sized {
    fn new_alphabetic(value: impl Into<Cow<'x, str>>) -> Self;
    fn unwrap_alphabetic(self) -> Cow<'x, str>;
    fn is_alphabetic(&self) -> bool;
    fn is_alphabetic_8bit(&self) -> bool;
}

impl<'x> InnerToken<'x> for Cow<'x, str> {
    fn new_alphabetic(value: impl Into<Cow<'x, str>>) -> Self {
        value.into()
    }

    fn is_alphabetic(&self) -> bool {
        true
    }

    fn is_alphabetic_8bit(&self) -> bool {
        !self.chars().all(|c| c.is_ascii())
    }

    fn unwrap_alphabetic(self) -> Cow<'x, str> {
        self
    }
}

impl<T> Token<T> {
    pub fn new(offset: usize, len: usize, word: T) -> Token<T> {
        debug_assert!(offset <= u32::MAX as usize);
        debug_assert!(len <= u8::MAX as usize);
        Token {
            from: offset,
            to: offset + len,
            word,
        }
    }
}
