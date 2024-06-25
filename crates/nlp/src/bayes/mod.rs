/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::HashMap, hash::BuildHasherDefault};

use nohash::NoHashHasher;
use serde::{Deserialize, Serialize};

use crate::tokenizers::osb::Gram;

pub mod cache;
pub mod classify;
pub mod tokenize;
pub mod train;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct BayesModel {
    pub weights: HashMap<TokenHash, Weights, BuildHasherDefault<NoHashHasher<TokenHash>>>,
    pub spam_learns: u32,
    pub ham_learns: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayesClassifier {
    pub min_token_hits: u32,
    pub min_tokens: u32,
    pub min_prob_strength: f64,
    pub min_learns: u32,
}

#[derive(Debug, Serialize, Deserialize, Default, Copy, Clone, PartialEq, Eq)]
pub struct TokenHash {
    pub h1: u64,
    pub h2: u64,
}

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
        match value {
            Gram::Uni { t1 } => TokenHash {
                h1: xxhash_rust::xxh3::xxh3_64(t1.as_bytes()),
                h2: farmhash::hash64(t1.as_bytes()),
            },
            Gram::Bi { t1, t2, .. } => {
                let mut buf = Vec::with_capacity(t1.len() + t2.len() + 1);
                buf.extend_from_slice(t1.as_bytes());
                buf.push(b' ');
                buf.extend_from_slice(t2.as_bytes());
                TokenHash {
                    h1: xxhash_rust::xxh3::xxh3_64(&buf),
                    h2: farmhash::hash64(&buf),
                }
            }
        }
    }
}

impl std::hash::Hash for TokenHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.h1 ^ self.h2);
    }
}

impl nohash::IsEnabled for TokenHash {}

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
        (value.ham as i64) << 32 | value.spam as i64
    }
}
