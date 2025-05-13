/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Deref;

#[derive(
    Debug, serde::Serialize, serde::Deserialize, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash,
)]
pub struct Bitmap<T: BitmapItem> {
    pub bitmap: u64,
    #[serde(skip)]
    _state: std::marker::PhantomData<T>,
}

pub trait BitmapItem: From<u64> + Into<u64> + Sized + Copy {
    fn max() -> u64;
    fn is_valid(&self) -> bool;
}

impl<T: BitmapItem> Bitmap<T> {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline(always)]
    pub fn all() -> Self {
        Self {
            bitmap: u64::MAX >> (64 - T::max()),
            _state: std::marker::PhantomData,
        }
    }

    #[inline(always)]
    pub fn union(&mut self, items: &Bitmap<T>) {
        self.bitmap |= items.bitmap;
    }

    #[inline(always)]
    pub fn intersection(&mut self, items: &Bitmap<T>) {
        self.bitmap &= items.bitmap;
    }

    #[inline(always)]
    pub fn insert(&mut self, item: T) {
        debug_assert!(item.is_valid());
        self.bitmap |= 1 << item.into();
    }

    #[inline(always)]
    pub fn with_item(mut self, item: T) -> Self {
        self.insert(item);
        self
    }

    #[inline(always)]
    pub fn remove(&mut self, item: T) {
        debug_assert!(item.is_valid());
        self.bitmap ^= 1 << item.into();
    }

    #[inline(always)]
    pub fn pop(&mut self) -> Option<T> {
        if self.bitmap != 0 {
            let item = 63 - self.bitmap.leading_zeros();
            self.bitmap ^= 1 << item;
            Some((item as u64).into())
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn contains(&self, item: T) -> bool {
        self.bitmap & (1 << item.into()) != 0
    }

    #[inline(always)]
    pub fn contains_any(&self, items: impl Iterator<Item = T>) -> bool {
        for item in items {
            if self.bitmap & (1 << item.into()) != 0 {
                return true;
            }
        }
        false
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.bitmap == 0
    }

    #[inline(always)]
    pub fn clear(&mut self) -> Self {
        let bitmap = self.bitmap;
        self.bitmap = 0;
        Bitmap {
            bitmap,
            _state: std::marker::PhantomData,
        }
    }
}

impl<T: BitmapItem> From<u64> for Bitmap<T> {
    fn from(value: u64) -> Self {
        Self {
            bitmap: value,
            _state: std::marker::PhantomData,
        }
    }
}

impl<T: BitmapItem> AsRef<u64> for Bitmap<T> {
    fn as_ref(&self) -> &u64 {
        &self.bitmap
    }
}

impl<T: BitmapItem> Deref for Bitmap<T> {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.bitmap
    }
}

impl<T: BitmapItem> From<Bitmap<T>> for u64 {
    fn from(value: Bitmap<T>) -> Self {
        value.bitmap
    }
}

impl<T: BitmapItem> Iterator for Bitmap<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bitmap != 0 {
            let item = 63 - self.bitmap.leading_zeros();
            self.bitmap ^= 1 << item;
            Some((item as u64).into())
        } else {
            None
        }
    }
}

impl<T: BitmapItem> From<Vec<T>> for Bitmap<T> {
    fn from(values: Vec<T>) -> Self {
        let mut bitmap = Bitmap::default();
        for value in values {
            if value.is_valid() {
                bitmap.insert(value);
            }
        }
        bitmap
    }
}

impl<T: BitmapItem> FromIterator<T> for Bitmap<T> {
    fn from_iter<U: IntoIterator<Item = T>>(iter: U) -> Self {
        let mut bitmap = Bitmap::new();
        for value in iter {
            if value.is_valid() {
                bitmap.insert(value);
            }
        }
        bitmap
    }
}

impl<T: BitmapItem> From<&Vec<T>> for Bitmap<T> {
    fn from(values: &Vec<T>) -> Self {
        let mut bitmap = Bitmap::default();
        for value in values {
            if value.is_valid() {
                bitmap.insert(*value);
            }
        }
        bitmap
    }
}

impl<T: BitmapItem> From<T> for Bitmap<T> {
    fn from(value: T) -> Self {
        let mut bitmap = Bitmap::default();
        bitmap.insert(value);
        bitmap
    }
}

impl<T: BitmapItem> From<Bitmap<T>> for Vec<T> {
    fn from(values: Bitmap<T>) -> Self {
        let mut list = Vec::new();
        for item in values {
            list.push(item);
        }
        list
    }
}

impl<T: BitmapItem> Default for Bitmap<T> {
    fn default() -> Self {
        Bitmap {
            bitmap: 0,
            _state: std::marker::PhantomData,
        }
    }
}
