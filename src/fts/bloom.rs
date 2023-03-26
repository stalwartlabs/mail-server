use std::{
    borrow::Cow,
    f64::consts::LN_2,
    hash::{Hash, Hasher},
};

use roaring::RoaringBitmap;
use utils::codec::leb128::{Leb128Reader, Leb128Vec};

use crate::{Deserialize, Serialize};

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

impl BloomHash {
    pub fn hash<T: Hash + AsRef<[u8]> + ?Sized>(item: &T) -> Self {
        let h1 = xxhash_rust::xxh3::xxh3_64(item.as_ref());
        let h2 = farmhash::hash64(item.as_ref());
        /*let h2 = naive_cityhash::cityhash64_with_seeds(
            item.as_ref(),
            0x99693e7c5b56f555,
            0x34809fd70b6ebf45,
        );*/
        let h3 = AHASHER.hash_one(item);
        let mut sh = *SIPHASHER;
        sh.write(item.as_ref());
        let h4 = sh.finish();

        Self {
            h: [h1, h2, h3, h4, h1 ^ h2, h2 ^ h3, h3 ^ h4],
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
    fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (m, pos) = bytes.read_leb128()?;
        let b = RoaringBitmap::deserialize_unchecked_from(bytes.get(pos..)?).ok()?;

        Some(Self::from_params(m, b))
    }
}
