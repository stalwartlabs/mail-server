/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::{HashMap, HashSet};

use sieve::{runtime::Variable, Context};

pub fn fn_count<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    match &v[0] {
        Variable::Array(a) => a.len(),
        v => {
            if !v.is_empty() {
                1
            } else {
                0
            }
        }
    }
    .into()
}

pub fn fn_sort<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    let is_asc = v[1].to_bool();
    let mut arr = (*v[0].to_array()).clone();
    if is_asc {
        arr.sort_unstable_by(|a, b| b.cmp(a));
    } else {
        arr.sort_unstable();
    }
    arr.into()
}

pub fn fn_dedup<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    let arr = v[0].to_array();
    let mut result = Vec::with_capacity(arr.len());

    for item in arr.iter() {
        if !result.contains(item) {
            result.push(item.clone());
        }
    }

    result.into()
}

pub fn fn_cosine_similarity<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    let mut word_freq: HashMap<Variable, [u32; 2]> = HashMap::new();

    for (idx, var) in v.into_iter().enumerate() {
        match var {
            Variable::Array(l) => {
                for item in l.iter() {
                    word_freq.entry(item.clone()).or_insert([0, 0])[idx] += 1;
                }
            }
            _ => {
                for char in var.to_string().chars() {
                    word_freq.entry(char.to_string().into()).or_insert([0, 0])[idx] += 1;
                }
            }
        }
    }

    let mut dot_product = 0;
    let mut magnitude_a = 0;
    let mut magnitude_b = 0;

    for (_word, count) in word_freq.iter() {
        dot_product += count[0] * count[1];
        magnitude_a += count[0] * count[0];
        magnitude_b += count[1] * count[1];
    }

    if magnitude_a != 0 && magnitude_b != 0 {
        dot_product as f64 / (magnitude_a as f64).sqrt() / (magnitude_b as f64).sqrt()
    } else {
        0.0
    }
    .into()
}

pub fn fn_jaccard_similarity<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    let mut word_freq = [HashSet::new(), HashSet::new()];

    for (idx, var) in v.into_iter().enumerate() {
        match var {
            Variable::Array(l) => {
                for item in l.iter() {
                    word_freq[idx].insert(item.clone());
                }
            }
            _ => {
                for char in var.to_string().chars() {
                    word_freq[idx].insert(char.to_string().into());
                }
            }
        }
    }

    let intersection_size = word_freq[0].intersection(&word_freq[1]).count();
    let union_size = word_freq[0].union(&word_freq[1]).count();

    if union_size != 0 {
        intersection_size as f64 / union_size as f64
    } else {
        0.0
    }
    .into()
}

pub fn fn_is_intersect<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    match (&v[0], &v[1]) {
        (Variable::Array(a), Variable::Array(b)) => a.iter().any(|x| b.contains(x)),
        (Variable::Array(a), item) | (item, Variable::Array(a)) => a.contains(item),
        _ => false,
    }
    .into()
}

pub fn fn_winnow<'x>(_: &'x Context<'x>, mut v: Vec<Variable>) -> Variable {
    match v.remove(0) {
        Variable::Array(a) => a
            .iter()
            .filter(|i| !i.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .into(),
        v => v,
    }
}
