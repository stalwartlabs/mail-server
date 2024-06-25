/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, iter::Peekable};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OsbToken<T> {
    pub inner: T,
    pub idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gram<'x> {
    Uni { t1: &'x str },
    Bi { t1: &'x str, t2: &'x str },
}

pub struct OsbTokenizer<'x, I, R>
where
    I: Iterator<Item = Cow<'x, str>>,
    R: for<'y> From<Gram<'y>> + 'static,
{
    iter: Peekable<I>,
    buf: Vec<Option<Cow<'x, str>>>,
    window_size: usize,
    window_pos: usize,
    window_idx: usize,
    phantom: std::marker::PhantomData<R>,
}

impl<'x, I, R> OsbTokenizer<'x, I, R>
where
    I: Iterator<Item = Cow<'x, str>>,
    R: for<'y> From<Gram<'y>> + 'static,
{
    pub fn new(iter: I, window_size: usize) -> Self {
        Self {
            iter: iter.peekable(),
            buf: vec![None; window_size],
            window_pos: 0,
            window_idx: 0,
            window_size,
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'x, I, R> Iterator for OsbTokenizer<'x, I, R>
where
    I: Iterator<Item = Cow<'x, str>>,
    R: for<'y> From<Gram<'y>> + 'static,
{
    type Item = OsbToken<R>;

    fn next(&mut self) -> Option<Self::Item> {
        let end_pos = (self.window_pos + self.window_idx) % self.window_size;
        if self.buf[end_pos].is_none() {
            self.buf[end_pos] = self.iter.next();
        }

        let t1 = self.buf[self.window_pos % self.window_size].as_deref()?;
        let token = OsbToken {
            inner: R::from(if self.window_idx != 0 {
                Gram::Bi {
                    t1,
                    t2: self.buf[end_pos].as_deref()?,
                }
            } else {
                Gram::Uni { t1 }
            }),
            idx: self.window_idx,
        };

        // Increment window index
        self.window_idx += 1;
        if self.window_idx == self.window_size
            || (self.iter.peek().is_none()
                && self.buf[(self.window_pos + self.window_idx) % self.window_size].is_none())
        {
            self.buf[self.window_pos % self.window_size] = None;
            self.window_idx = 0;
            self.window_pos += 1;
        }

        Some(token)
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use crate::tokenizers::osb::{Gram, OsbToken};

    impl From<Gram<'_>> for String {
        fn from(value: Gram<'_>) -> Self {
            match value {
                Gram::Uni { t1 } => t1.to_string(),
                Gram::Bi { t1, t2 } => format!("{t1} {t2}"),
            }
        }
    }

    #[test]
    fn osb_tokenizer() {
        assert_eq!(
            super::OsbTokenizer::new(
                "The quick brown fox jumps over the lazy dog and the lazy cat"
                    .split_ascii_whitespace()
                    .map(Cow::from),
                5,
            )
            .collect::<Vec<_>>(),
            vec![
                OsbToken {
                    inner: "The".to_string(),
                    idx: 0
                },
                OsbToken {
                    inner: "The quick".to_string(),
                    idx: 1
                },
                OsbToken {
                    inner: "The brown".to_string(),
                    idx: 2
                },
                OsbToken {
                    inner: "The fox".to_string(),
                    idx: 3
                },
                OsbToken {
                    inner: "The jumps".to_string(),
                    idx: 4
                },
                OsbToken {
                    inner: "quick".to_string(),
                    idx: 0
                },
                OsbToken {
                    inner: "quick brown".to_string(),
                    idx: 1
                },
                OsbToken {
                    inner: "quick fox".to_string(),
                    idx: 2
                },
                OsbToken {
                    inner: "quick jumps".to_string(),
                    idx: 3
                },
                OsbToken {
                    inner: "quick over".to_string(),
                    idx: 4
                },
                OsbToken {
                    inner: "brown".to_string(),
                    idx: 0
                },
                OsbToken {
                    inner: "brown fox".to_string(),
                    idx: 1
                },
                OsbToken {
                    inner: "brown jumps".to_string(),
                    idx: 2
                },
                OsbToken {
                    inner: "brown over".to_string(),
                    idx: 3
                },
                OsbToken {
                    inner: "brown the".to_string(),
                    idx: 4
                },
                OsbToken {
                    inner: "fox".to_string(),
                    idx: 0
                },
                OsbToken {
                    inner: "fox jumps".to_string(),
                    idx: 1
                },
                OsbToken {
                    inner: "fox over".to_string(),
                    idx: 2
                },
                OsbToken {
                    inner: "fox the".to_string(),
                    idx: 3
                },
                OsbToken {
                    inner: "fox lazy".to_string(),
                    idx: 4
                },
                OsbToken {
                    inner: "jumps".to_string(),
                    idx: 0
                },
                OsbToken {
                    inner: "jumps over".to_string(),
                    idx: 1
                },
                OsbToken {
                    inner: "jumps the".to_string(),
                    idx: 2
                },
                OsbToken {
                    inner: "jumps lazy".to_string(),
                    idx: 3
                },
                OsbToken {
                    inner: "jumps dog".to_string(),
                    idx: 4
                },
                OsbToken {
                    inner: "over".to_string(),
                    idx: 0
                },
                OsbToken {
                    inner: "over the".to_string(),
                    idx: 1
                },
                OsbToken {
                    inner: "over lazy".to_string(),
                    idx: 2
                },
                OsbToken {
                    inner: "over dog".to_string(),
                    idx: 3
                },
                OsbToken {
                    inner: "over and".to_string(),
                    idx: 4
                },
                OsbToken {
                    inner: "the".to_string(),
                    idx: 0
                },
                OsbToken {
                    inner: "the lazy".to_string(),
                    idx: 1
                },
                OsbToken {
                    inner: "the dog".to_string(),
                    idx: 2
                },
                OsbToken {
                    inner: "the and".to_string(),
                    idx: 3
                },
                OsbToken {
                    inner: "the the".to_string(),
                    idx: 4
                },
                OsbToken {
                    inner: "lazy".to_string(),
                    idx: 0
                },
                OsbToken {
                    inner: "lazy dog".to_string(),
                    idx: 1
                },
                OsbToken {
                    inner: "lazy and".to_string(),
                    idx: 2
                },
                OsbToken {
                    inner: "lazy the".to_string(),
                    idx: 3
                },
                OsbToken {
                    inner: "lazy lazy".to_string(),
                    idx: 4
                },
                OsbToken {
                    inner: "dog".to_string(),
                    idx: 0
                },
                OsbToken {
                    inner: "dog and".to_string(),
                    idx: 1
                },
                OsbToken {
                    inner: "dog the".to_string(),
                    idx: 2
                },
                OsbToken {
                    inner: "dog lazy".to_string(),
                    idx: 3
                },
                OsbToken {
                    inner: "dog cat".to_string(),
                    idx: 4
                },
                OsbToken {
                    inner: "and".to_string(),
                    idx: 0
                },
                OsbToken {
                    inner: "and the".to_string(),
                    idx: 1
                },
                OsbToken {
                    inner: "and lazy".to_string(),
                    idx: 2
                },
                OsbToken {
                    inner: "and cat".to_string(),
                    idx: 3
                },
                OsbToken {
                    inner: "the".to_string(),
                    idx: 0
                },
                OsbToken {
                    inner: "the lazy".to_string(),
                    idx: 1
                },
                OsbToken {
                    inner: "the cat".to_string(),
                    idx: 2
                },
                OsbToken {
                    inner: "lazy".to_string(),
                    idx: 0
                },
                OsbToken {
                    inner: "lazy cat".to_string(),
                    idx: 1
                },
                OsbToken {
                    inner: "cat".to_string(),
                    idx: 0
                }
            ]
        );
    }
}
