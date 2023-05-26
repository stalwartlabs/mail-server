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

use std::{
    borrow::Cow,
    f64::consts::LN_2,
    hash::{Hash, Hasher},
};

use roaring::RoaringBitmap;
use utils::codec::leb128::{Leb128Reader, Leb128Vec};

use crate::{Deserialize, Error, Serialize};

use super::{stemmer::StemmedToken, tokenizers::Token};

pub struct BloomFilter {
    m: u64,
    b: RoaringBitmap,
}

#[derive(Debug)]
pub struct BloomHash {
    pub h: [u64; 7],
}

#[derive(Debug)]
pub struct BloomHashGroup {
    pub h1: BloomHash,
    pub h2: Option<BloomHash>,
}

const AHASHER: ahash::RandomState = ahash::RandomState::with_seeds(
    0xaf1f2242106c64b3,
    0x60ca4cfb4b3ed0ce,
    0xc7dbc0bb615e82b3,
    0x520ad065378daf88,
);
lazy_static::lazy_static! {
    static ref SIPHASHER: siphasher::sip::SipHasher13 =
        siphasher::sip::SipHasher13::new_with_keys(0x56205cbdba8f02a6, 0xbd0dbc4bb06d687b);
}

const P: f64 = 0.01;

impl BloomFilter {
    pub fn new(items: usize) -> Self {
        Self {
            m: if items > 0 {
                std::cmp::max(Self::estimate_m(items, P), 10240)
            } else {
                0
            },
            b: RoaringBitmap::new(),
        }
    }

    fn from_params(m: u64, b: RoaringBitmap) -> Self {
        Self { m, b }
    }

    fn estimate_m(n: usize, p: f64) -> u64 {
        (((n as f64) * f64::ln(p) / (-8.0 * LN_2.powi(2))).ceil() as u64) * 8
    }

    #[allow(dead_code)]
    fn estimate_k(m: u64, n: usize) -> u32 {
        std::cmp::max(((m as f64) / (n as f64) * f64::ln(2.0f64)).ceil() as u32, 1)
    }

    pub fn insert(&mut self, hash: &BloomHash) {
        self.b.insert((hash.h[0] % self.m) as u32);
        self.b.insert((hash.h[1] % self.m) as u32);
        self.b.insert((hash.h[2] % self.m) as u32);
        self.b.insert((hash.h[3] % self.m) as u32);
        self.b.insert((hash.h[4] % self.m) as u32);
        self.b.insert((hash.h[5] % self.m) as u32);
        self.b.insert((hash.h[6] % self.m) as u32);
    }

    pub fn contains(&self, hash: &BloomHash) -> bool {
        self.b.contains((hash.h[0] % self.m) as u32)
            && self.b.contains((hash.h[1] % self.m) as u32)
            && self.b.contains((hash.h[2] % self.m) as u32)
            && self.b.contains((hash.h[3] % self.m) as u32)
            && self.b.contains((hash.h[4] % self.m) as u32)
            && self.b.contains((hash.h[5] % self.m) as u32)
            && self.b.contains((hash.h[6] % self.m) as u32)
    }

    pub fn is_subset(&self, other: &Self) -> bool {
        self.b.is_subset(&other.b)
    }

    pub fn is_empty(&self) -> bool {
        self.m == 0 || self.b.is_empty()
    }
}

pub trait BloomHasher {
    fn hash<T: Hash + AsRef<[u8]> + ?Sized>(item: &T) -> Self;
}

impl BloomHash {
    pub fn hash<T: Hash + AsRef<[u8]> + ?Sized>(item: &T) -> Self {
        let h1 = xxhash_rust::xxh3::xxh3_64(item.as_ref());
        let h2 = farmhash::hash64(item.as_ref());
        let h3 = AHASHER.hash_one(item);
        let mut sh = *SIPHASHER;
        sh.write(item.as_ref());
        let h4 = sh.finish();

        Self {
            h: [h1, h2, h3, h4, h1 ^ h2, h2 ^ h3, h3 ^ h4],
        }
    }
}

pub fn hash_token(item: &str) -> Vec<u8> {
    let h1 = xxhash_rust::xxh3::xxh3_64(item.as_ref()).to_le_bytes();
    let h2 = farmhash::hash64(item.as_ref()).to_le_bytes();
    let h3 = AHASHER.hash_one(item).to_le_bytes();
    let mut sh = *SIPHASHER;
    sh.write(item.as_ref());
    let h4 = sh.finish().to_le_bytes();

    match item.len() {
        0..=8 => {
            let mut hash = Vec::with_capacity(6);
            hash.extend_from_slice(&h1[..2]);
            hash.extend_from_slice(&h2[..2]);
            hash.push(h3[0]);
            hash.push(h4[0]);
            hash
        }
        9..=16 => {
            let mut hash = Vec::with_capacity(8);
            hash.extend_from_slice(&h1[..2]);
            hash.extend_from_slice(&h2[..2]);
            hash.extend_from_slice(&h3[..2]);
            hash.extend_from_slice(&h4[..2]);
            hash
        }
        17..=32 => {
            let mut hash = Vec::with_capacity(12);
            hash.extend_from_slice(&h1[..3]);
            hash.extend_from_slice(&h2[..3]);
            hash.extend_from_slice(&h3[..3]);
            hash.extend_from_slice(&h4[..3]);
            hash
        }
        _ => {
            let mut hash = Vec::with_capacity(16);
            hash.extend_from_slice(&h1[..4]);
            hash.extend_from_slice(&h2[..4]);
            hash.extend_from_slice(&h3[..4]);
            hash.extend_from_slice(&h4[..4]);
            hash
        }
    }
}

impl From<&str> for BloomHash {
    fn from(s: &str) -> Self {
        Self::hash(&s)
    }
}

impl From<String> for BloomHash {
    fn from(s: String) -> Self {
        Self::hash(&s)
    }
}

impl From<&String> for BloomHash {
    fn from(s: &String) -> Self {
        Self::hash(&s)
    }
}

impl From<Cow<'_, str>> for BloomHash {
    fn from(s: Cow<'_, str>) -> Self {
        Self::hash(s.as_ref())
    }
}

impl From<Token<'_>> for BloomHashGroup {
    fn from(t: Token<'_>) -> Self {
        Self {
            h1: BloomHash::hash(t.word.as_ref()),
            h2: None,
        }
    }
}

impl From<StemmedToken<'_>> for BloomHashGroup {
    fn from(t: StemmedToken<'_>) -> Self {
        Self {
            h1: BloomHash::hash(t.word.as_ref()),
            h2: t.stemmed_word.map(|w| BloomHash::hash(&format!("{w}_"))),
        }
    }
}

impl From<Cow<'_, str>> for BloomHashGroup {
    fn from(t: Cow<'_, str>) -> Self {
        Self {
            h1: BloomHash::hash(t.as_ref()),
            h2: None,
        }
    }
}

impl Serialize for BloomFilter {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(std::mem::size_of::<u64>() + self.b.serialized_size());
        buf.push_leb128(self.m);
        let _ = self.b.serialize_into(&mut buf);
        buf
    }
}

impl Deserialize for BloomFilter {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        let (m, pos) = bytes.read_leb128().ok_or_else(|| {
            Error::InternalError(
                "Failed to read 'm' value while deserializing bloom filter.".to_string(),
            )
        })?;
        RoaringBitmap::deserialize_unchecked_from(bytes.get(pos..).ok_or_else(|| {
            Error::InternalError(
                "Failed to read bitmap while deserializing bloom filter.".to_string(),
            )
        })?)
        .map_err(|err| Error::InternalError(format!("Failed to deserialize bloom filter: {err}.")))
        .map(|b| Self::from_params(m, b))
    }
}
