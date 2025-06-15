/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use radix_trie::TrieKey;
use serde::{Deserialize, Serialize};
use utils::cache::CacheItemWeight;

use crate::tokenizers::osb::Gram;

pub mod classify;
pub mod tokenize;
pub mod train;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct BayesModel {
    pub weights: AHashMap<TokenHash, Weights>,
    pub spam_learns: u32,
    pub ham_learns: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayesClassifier {
    pub min_token_hits: u32,
    pub min_tokens: u32,
    pub min_prob_strength: f64,
    pub min_learns: u32,
    pub min_balance: f64,
}

#[derive(Debug, Serialize, Deserialize, Default, Copy, Clone, PartialEq, Eq, Hash)]
pub struct TokenHash {
    hash: [u8; HASH_LEN],
    len: u8,
}
const HASH_LEN: usize = std::mem::size_of::<u64>() * 2;

#[derive(Debug, Serialize, Deserialize, Default, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Weights {
    pub spam: u32,
    pub ham: u32,
}

impl BayesClassifier {
    pub fn new() -> Self {
        BayesClassifier {
            min_token_hits: 2,
            min_tokens: 11,
            min_prob_strength: 0.05,
            min_learns: 200,
            min_balance: 0.1,
        }
    }
}

impl Default for BayesClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Gram<'_>> for TokenHash {
    fn from(value: Gram<'_>) -> Self {
        let mut hash = TokenHash {
            hash: [0; HASH_LEN],
            len: 0,
        };

        match value {
            Gram::Uni { t1 } => {
                if t1.len() <= HASH_LEN {
                    hash.hash[..t1.len()].copy_from_slice(t1);
                    hash.len = t1.len() as u8;
                } else {
                    let h1 = xxhash_rust::xxh3::xxh3_64(t1).to_be_bytes();
                    let h2 = farmhash::hash64(t1).to_be_bytes();
                    hash.hash[..std::mem::size_of::<u64>()].copy_from_slice(&h1);
                    hash.hash[std::mem::size_of::<u64>()..].copy_from_slice(&h2);
                    hash.len = HASH_LEN as u8;
                }
            }
            Gram::Bi { t1, t2, .. } => {
                let len = t1.len() + t2.len() + 1;
                if len <= HASH_LEN {
                    for (h, b) in hash.hash.iter_mut().zip(
                        t1.iter()
                            .copied()
                            .chain([b' '].into_iter())
                            .chain(t2.iter().copied()),
                    ) {
                        *h = b;
                    }
                    hash.len = len as u8;
                } else if t1.len() <= std::mem::size_of::<u64>() {
                    for (h, b) in hash.hash.iter_mut().zip(
                        t1.iter()
                            .copied()
                            .chain(xxhash_rust::xxh3::xxh3_64(t2).to_be_bytes().into_iter())
                            .chain(farmhash::hash64(t2).to_be_bytes().into_iter()),
                    ) {
                        *h = b;
                    }
                    hash.len = HASH_LEN as u8;
                } else {
                    let mut buf = Vec::with_capacity(t1.len() + t2.len() + 1);
                    buf.extend_from_slice(t1);
                    buf.push(b' ');
                    buf.extend_from_slice(t2);
                    let h1 = xxhash_rust::xxh3::xxh3_64(&buf).to_be_bytes();
                    let h2 = farmhash::fingerprint64(&buf).to_be_bytes();
                    hash.hash[..std::mem::size_of::<u64>()].copy_from_slice(&h1);
                    hash.hash[std::mem::size_of::<u64>()..].copy_from_slice(&h2);
                    hash.len = HASH_LEN as u8;
                }
            }
        }

        hash
    }
}

impl TrieKey for TokenHash {
    fn encode_bytes(&self) -> Vec<u8> {
        self.hash[..self.len as usize].to_vec()
    }
}

impl From<i64> for Weights {
    fn from(value: i64) -> Self {
        Weights {
            spam: value as u32,
            ham: (value >> 32) as u32,
        }
    }
}

impl From<Weights> for i64 {
    fn from(value: Weights) -> Self {
        ((value.ham as i64) << 32) | value.spam as i64
    }
}

impl CacheItemWeight for Weights {
    fn weight(&self) -> u64 {
        std::mem::size_of::<u64>() as u64
    }
}

impl CacheItemWeight for TokenHash {
    fn weight(&self) -> u64 {
        std::mem::size_of::<TokenHash>() as u64
    }
}

impl TokenHash {
    pub fn serialize(&self, prefix: u8, account_id: Option<u32>) -> Vec<u8> {
        if let Some(account_id) = account_id {
            self.serialize_account(prefix, account_id)
        } else {
            self.serialize_global(prefix)
        }
    }

    pub fn serialize_global(&self, prefix: u8) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.len as usize + 1);
        buf.push(prefix);
        if self.len > 0 {
            buf.extend_from_slice(&self.hash[..self.len as usize]);
        }
        buf
    }

    pub fn serialize_account(&self, prefix: u8, account_id: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(std::mem::size_of::<u32>() + self.len as usize + 1);
        buf.push(prefix);
        buf.extend_from_slice(&account_id.to_be_bytes());
        if self.len > 0 {
            buf.extend_from_slice(&self.hash[..self.len as usize]);
        }
        buf
    }
}
