use std::borrow::Cow;

use super::bloom::{BloomFilter, BloomHashGroup};

pub trait ToNgrams: Sized {
    fn new(items: usize) -> Self;
    fn insert(&mut self, item: &str);
    fn to_ngrams(tokens: &[Cow<'_, str>], n: usize) -> Self {
        let mut filter = Self::new(tokens.len().saturating_sub(1));
        for words in tokens.windows(n) {
            filter.insert(&words.join(" "));
        }
        filter
    }
}

impl ToNgrams for BloomFilter {
    fn new(items: usize) -> Self {
        BloomFilter::new(items)
    }

    fn insert(&mut self, item: &str) {
        self.insert(&item.into())
    }
}

impl ToNgrams for Vec<BloomHashGroup> {
    fn new(items: usize) -> Self {
        Vec::with_capacity(items)
    }

    fn insert(&mut self, item: &str) {
        self.push(BloomHashGroup {
            h1: item.into(),
            h2: None,
        })
    }
}
