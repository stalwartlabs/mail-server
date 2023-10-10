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

use std::iter::Peekable;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsbToken<T> {
    pub inner: T,
    pub idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gram<'x> {
    Uni { t1: &'x str },
    Bi { t1: &'x str, t2: &'x str },
}

pub struct OsbTokenizer<'x, I>
where
    I: Iterator<Item = &'x str>,
{
    iter: Peekable<I>,
    buf: Vec<Option<&'x str>>,
    window_size: usize,
    window_pos: usize,
    window_idx: usize,
}

impl<'x, I> OsbTokenizer<'x, I>
where
    I: Iterator<Item = &'x str>,
{
    pub fn new(iter: I, window_size: usize) -> Self {
        Self {
            iter: iter.peekable(),
            buf: vec![None; window_size],
            window_pos: 0,
            window_idx: 0,
            window_size,
        }
    }
}

impl<'x, I> Iterator for OsbTokenizer<'x, I>
where
    I: Iterator<Item = &'x str>,
{
    type Item = OsbToken<Gram<'x>>;

    fn next(&mut self) -> Option<Self::Item> {
        let end_pos = (self.window_pos + self.window_idx) % self.window_size;
        if self.buf[end_pos].is_none() {
            self.buf[end_pos] = self.iter.next();
        }

        let t1 = self.buf[self.window_pos % self.window_size]?;
        let token = OsbToken {
            inner: if self.window_idx != 0 {
                Gram::Bi {
                    t1,
                    t2: self.buf[end_pos]?,
                }
            } else {
                Gram::Uni { t1 }
            },
            idx: self.window_idx,
        };

        // Increment window
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
    use crate::transformers::osb::{Gram, OsbToken};

    #[test]
    fn osb_tokenizer() {
        assert_eq!(
            super::OsbTokenizer::new(
                "The quick brown fox jumps over the lazy dog and the lazy cat"
                    .split_ascii_whitespace(),
                5
            )
            .collect::<Vec<_>>(),
            vec![
                OsbToken {
                    inner: Gram::Uni { t1: "The" },
                    idx: 0
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "The",
                        t2: "quick"
                    },
                    idx: 1
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "The",
                        t2: "brown"
                    },
                    idx: 2
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "The",
                        t2: "fox"
                    },
                    idx: 3
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "The",
                        t2: "jumps"
                    },
                    idx: 4
                },
                OsbToken {
                    inner: Gram::Uni { t1: "quick" },
                    idx: 0
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "quick",
                        t2: "brown"
                    },
                    idx: 1
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "quick",
                        t2: "fox"
                    },
                    idx: 2
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "quick",
                        t2: "jumps"
                    },
                    idx: 3
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "quick",
                        t2: "over"
                    },
                    idx: 4
                },
                OsbToken {
                    inner: Gram::Uni { t1: "brown" },
                    idx: 0
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "brown",
                        t2: "fox"
                    },
                    idx: 1
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "brown",
                        t2: "jumps"
                    },
                    idx: 2
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "brown",
                        t2: "over"
                    },
                    idx: 3
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "brown",
                        t2: "the"
                    },
                    idx: 4
                },
                OsbToken {
                    inner: Gram::Uni { t1: "fox" },
                    idx: 0
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "fox",
                        t2: "jumps"
                    },
                    idx: 1
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "fox",
                        t2: "over"
                    },
                    idx: 2
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "fox",
                        t2: "the"
                    },
                    idx: 3
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "fox",
                        t2: "lazy"
                    },
                    idx: 4
                },
                OsbToken {
                    inner: Gram::Uni { t1: "jumps" },
                    idx: 0
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "jumps",
                        t2: "over"
                    },
                    idx: 1
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "jumps",
                        t2: "the"
                    },
                    idx: 2
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "jumps",
                        t2: "lazy"
                    },
                    idx: 3
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "jumps",
                        t2: "dog"
                    },
                    idx: 4
                },
                OsbToken {
                    inner: Gram::Uni { t1: "over" },
                    idx: 0
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "over",
                        t2: "the"
                    },
                    idx: 1
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "over",
                        t2: "lazy"
                    },
                    idx: 2
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "over",
                        t2: "dog"
                    },
                    idx: 3
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "over",
                        t2: "and"
                    },
                    idx: 4
                },
                OsbToken {
                    inner: Gram::Uni { t1: "the" },
                    idx: 0
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "the",
                        t2: "lazy"
                    },
                    idx: 1
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "the",
                        t2: "dog"
                    },
                    idx: 2
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "the",
                        t2: "and"
                    },
                    idx: 3
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "the",
                        t2: "the"
                    },
                    idx: 4
                },
                OsbToken {
                    inner: Gram::Uni { t1: "lazy" },
                    idx: 0
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "lazy",
                        t2: "dog"
                    },
                    idx: 1
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "lazy",
                        t2: "and"
                    },
                    idx: 2
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "lazy",
                        t2: "the"
                    },
                    idx: 3
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "lazy",
                        t2: "lazy"
                    },
                    idx: 4
                },
                OsbToken {
                    inner: Gram::Uni { t1: "dog" },
                    idx: 0
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "dog",
                        t2: "and"
                    },
                    idx: 1
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "dog",
                        t2: "the"
                    },
                    idx: 2
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "dog",
                        t2: "lazy"
                    },
                    idx: 3
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "dog",
                        t2: "cat"
                    },
                    idx: 4
                },
                OsbToken {
                    inner: Gram::Uni { t1: "and" },
                    idx: 0
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "and",
                        t2: "the"
                    },
                    idx: 1
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "and",
                        t2: "lazy"
                    },
                    idx: 2
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "and",
                        t2: "cat"
                    },
                    idx: 3
                },
                OsbToken {
                    inner: Gram::Uni { t1: "the" },
                    idx: 0
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "the",
                        t2: "lazy"
                    },
                    idx: 1
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "the",
                        t2: "cat"
                    },
                    idx: 2
                },
                OsbToken {
                    inner: Gram::Uni { t1: "lazy" },
                    idx: 0
                },
                OsbToken {
                    inner: Gram::Bi {
                        t1: "lazy",
                        t2: "cat"
                    },
                    idx: 1
                },
                OsbToken {
                    inner: Gram::Uni { t1: "cat" },
                    idx: 0
                }
            ]
        );
    }
}
