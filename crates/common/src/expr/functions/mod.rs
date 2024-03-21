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

use std::borrow::Cow;

use super::Variable;

pub mod array;
pub mod asynch;
pub mod email;
pub mod misc;
pub mod text;

pub trait ResolveVariable<'x> {
    fn resolve_variable(&self, variable: u32) -> Variable<'x>;
}

impl<'x> Variable<'x> {
    fn transform(self, f: impl Fn(Cow<'x, str>) -> Variable<'x>) -> Variable<'x> {
        match self {
            Variable::String(s) => f(s),
            Variable::Array(list) => Variable::Array(
                list.into_iter()
                    .map(|v| match v {
                        Variable::String(s) => f(s),
                        v => f(v.into_string()),
                    })
                    .collect::<Vec<_>>(),
            ),
            v => f(v.into_string()),
        }
    }
}

#[allow(clippy::type_complexity)]
pub(crate) const FUNCTIONS: &[(&str, fn(Vec<Variable>) -> Variable, u32)] = &[
    ("count", array::fn_count, 1),
    ("sort", array::fn_sort, 2),
    ("dedup", array::fn_dedup, 1),
    ("winnow", array::fn_winnow, 1),
    ("is_intersect", array::fn_is_intersect, 2),
    ("is_email", email::fn_is_email, 1),
    ("email_part", email::fn_email_part, 2),
    ("is_empty", misc::fn_is_empty, 1),
    ("is_number", misc::fn_is_number, 1),
    ("is_ip_addr", misc::fn_is_ip_addr, 1),
    ("is_ipv4_addr", misc::fn_is_ipv4_addr, 1),
    ("is_ipv6_addr", misc::fn_is_ipv6_addr, 1),
    ("ip_reverse_name", misc::fn_ip_reverse_name, 1),
    ("trim", text::fn_trim, 1),
    ("trim_end", text::fn_trim_end, 1),
    ("trim_start", text::fn_trim_start, 1),
    ("len", text::fn_len, 1),
    ("to_lowercase", text::fn_to_lowercase, 1),
    ("to_uppercase", text::fn_to_uppercase, 1),
    ("is_uppercase", text::fn_is_uppercase, 1),
    ("is_lowercase", text::fn_is_lowercase, 1),
    ("has_digits", text::fn_has_digits, 1),
    ("count_spaces", text::fn_count_spaces, 1),
    ("count_uppercase", text::fn_count_uppercase, 1),
    ("count_lowercase", text::fn_count_lowercase, 1),
    ("count_chars", text::fn_count_chars, 1),
    ("contains", text::fn_contains, 2),
    ("contains_ignore_case", text::fn_contains_ignore_case, 2),
    ("eq_ignore_case", text::fn_eq_ignore_case, 2),
    ("starts_with", text::fn_starts_with, 2),
    ("ends_with", text::fn_ends_with, 2),
    ("lines", text::fn_lines, 1),
    ("substring", text::fn_substring, 3),
    ("strip_prefix", text::fn_strip_prefix, 2),
    ("strip_suffix", text::fn_strip_suffix, 2),
    ("split", text::fn_split, 2),
    ("rsplit", text::fn_rsplit, 2),
    ("split_once", text::fn_split_once, 2),
    ("rsplit_once", text::fn_rsplit_once, 2),
    ("split_words", text::fn_split_words, 1),
];

pub const F_IS_LOCAL_DOMAIN: u32 = 0;
pub const F_IS_LOCAL_ADDRESS: u32 = 1;
pub const F_KEY_GET: u32 = 2;
pub const F_KEY_EXISTS: u32 = 3;
pub const F_KEY_SET: u32 = 4;
pub const F_COUNTER_INCR: u32 = 5;
pub const F_COUNTER_GET: u32 = 6;
pub const F_SQL_QUERY: u32 = 7;
pub const F_DNS_QUERY: u32 = 8;

pub const ASYNC_FUNCTIONS: &[(&str, u32, u32)] = &[
    ("is_local_domain", F_IS_LOCAL_DOMAIN, 2),
    ("is_local_address", F_IS_LOCAL_ADDRESS, 2),
    ("key_get", F_KEY_GET, 2),
    ("key_exists", F_KEY_EXISTS, 2),
    ("key_set", F_KEY_SET, 3),
    ("counter_incr", F_COUNTER_INCR, 3),
    ("counter_get", F_COUNTER_GET, 2),
    ("dns_query", F_DNS_QUERY, 2),
    ("sql_query", F_SQL_QUERY, 3),
];
