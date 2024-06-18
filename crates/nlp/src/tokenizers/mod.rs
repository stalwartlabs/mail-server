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
