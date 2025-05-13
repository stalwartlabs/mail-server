/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::expr::Variable;

pub(crate) fn fn_count(v: Vec<Variable>) -> Variable {
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

pub(crate) fn fn_sort(mut v: Vec<Variable>) -> Variable {
    let is_asc = v[1].to_bool();
    let mut arr = v.remove(0).into_array();
    if is_asc {
        arr.sort_unstable_by(|a, b| b.cmp(a));
    } else {
        arr.sort_unstable();
    }
    arr.into()
}

pub(crate) fn fn_dedup(mut v: Vec<Variable>) -> Variable {
    let arr = v.remove(0).into_array();
    let mut result = Vec::with_capacity(arr.len());

    for item in arr {
        if !result.contains(&item) {
            result.push(item);
        }
    }

    result.into()
}

pub(crate) fn fn_is_intersect(v: Vec<Variable>) -> Variable {
    match (&v[0], &v[1]) {
        (Variable::Array(a), Variable::Array(b)) => a.iter().any(|x| b.contains(x)),
        (Variable::Array(a), item) | (item, Variable::Array(a)) => a.contains(item),
        _ => false,
    }
    .into()
}

pub(crate) fn fn_winnow(mut v: Vec<Variable>) -> Variable {
    match v.remove(0) {
        Variable::Array(a) => a
            .into_iter()
            .filter(|i| !i.is_empty())
            .collect::<Vec<_>>()
            .into(),
        v => v,
    }
}
