/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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
