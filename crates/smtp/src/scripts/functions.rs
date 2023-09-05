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

use mail_parser::parsers::fields::thread::thread_name;
use sieve::{runtime::Variable, FunctionMap};

pub fn register_functions() -> FunctionMap {
    FunctionMap::new()
        .with_function("trim", |v| v.to_cow().trim().to_string().into())
        .with_function("len", |v| v.to_cow().len().into())
        .with_function("is_empty", |v| v.to_cow().as_ref().is_empty().into())
        .with_function("to_lowercase", |v| {
            v.to_cow().to_lowercase().to_string().into()
        })
        .with_function("to_uppercase", |v| {
            v.to_cow().to_uppercase().to_string().into()
        })
        .with_function("language", |v| {
            whatlang::detect_lang(v.to_cow().as_ref())
                .map(|l| l.code())
                .unwrap_or("unknown")
                .into()
        })
        .with_function("is_email", |v| is_email_valid(v.to_cow().as_ref()).into())
        .with_function("domain_part", |v| {
            v.to_cow()
                .rsplit_once('@')
                .map_or(Variable::default(), |(_, d)| d.trim().to_string().into())
        })
        .with_function("local_part", |v| {
            v.to_cow()
                .rsplit_once('@')
                .map_or(Variable::default(), |(u, _)| u.trim().to_string().into())
        })
        .with_function("domain_name_part", |v| {
            v.to_cow()
                .rsplit_once('@')
                .and_then(|(_, d)| d.trim().split('.').rev().nth(1).map(|s| s.to_string()))
                .map_or(Variable::default(), Variable::from)
        })
        .with_function("subdomain_part", |v| {
            v.to_cow()
                .rsplit_once('@')
                .map_or(Variable::default(), |(_, d)| {
                    d.split('.')
                        .rev()
                        .take(2)
                        .fold(String::new(), |a, b| {
                            if a.is_empty() {
                                b.to_string()
                            } else {
                                format!("{}.{}", b, a)
                            }
                        })
                        .into()
                })
        })
        .with_function("thread_name", |v| {
            thread_name(v.to_cow().as_ref()).to_string().into()
        })
        .with_function("is_uppercase", |v| {
            v.to_cow()
                .as_ref()
                .chars()
                .filter(|c| c.is_alphabetic())
                .all(|c| c.is_uppercase())
                .into()
        })
        .with_function("is_lowercase", |v| {
            v.to_cow()
                .as_ref()
                .chars()
                .filter(|c| c.is_alphabetic())
                .all(|c| c.is_lowercase())
                .into()
        })
        .with_function("count_words", |v| {
            v.to_cow().as_ref().split_whitespace().count().into()
        })
        .with_function("count_chars", |v| {
            v.to_cow().as_ref().chars().count().into()
        })
        .with_function("count_control_chars", |v| {
            v.to_cow()
                .as_ref()
                .chars()
                .filter(|c| {
                    matches!(c, '\u{0000}'..='\u{0008}'
                    | '\u{000B}'
                    | '\u{000C}'
                    | '\u{000E}'..='\u{001F}'
                    | '\u{007F}')
                })
                .count()
                .into()
        })
        .with_function("count", |v| {
            if let Variable::Array(l) = v {
                l.len().into()
            } else {
                1.into()
            }
        })
}

fn is_email_valid(email: &str) -> bool {
    let mut last_ch = 0;
    let mut in_quote = false;
    let mut at_count = 0;
    let mut dot_count = 0;
    let mut lp_len = 0;
    let mut value = 0;

    for ch in email.bytes() {
        match ch {
            b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'/'
            | b'='
            | b'?'
            | b'^'
            | b'_'
            | b'`'
            | b'{'
            | b'|'
            | b'}'
            | b'~'
            | 0x7f..=u8::MAX => {
                value += 1;
            }
            b'.' if !in_quote => {
                if last_ch != b'.' && last_ch != b'@' && value != 0 {
                    value += 1;
                    if at_count == 1 {
                        dot_count += 1;
                    }
                } else {
                    return false;
                }
            }
            b'@' if !in_quote => {
                at_count += 1;
                lp_len = value;
                value = 0;
            }
            b'>' | b':' | b',' | b' ' if in_quote => {
                value += 1;
            }
            b'\"' if !in_quote || last_ch != b'\\' => {
                in_quote = !in_quote;
            }
            b'\\' if in_quote && last_ch != b'\\' => (),
            _ => {
                if !in_quote {
                    return false;
                }
            }
        }

        last_ch = ch;
    }

    at_count == 1 && dot_count > 0 && lp_len > 0 && value > 0
}
