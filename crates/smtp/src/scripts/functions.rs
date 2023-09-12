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

use std::{borrow::Cow, collections::HashMap};

use ahash::{HashSet, HashSetExt};
use mail_parser::{
    decoders::html::html_to_text, parsers::fields::thread::thread_name, HeaderName, HeaderValue,
    MimeHeaders,
};
use sieve::{compiler::ReceivedPart, runtime::Variable, FunctionMap};

pub fn register_functions() -> FunctionMap {
    FunctionMap::new()
        .with_function("trim", |_, v| v[0].transform(|s| Some(s.trim())))
        .with_function("len", |_, v| {
            match &v[0] {
                Variable::String(s) => s.len(),
                Variable::StringRef(s) => s.len(),
                Variable::Array(a) => a.len(),
                Variable::ArrayRef(a) => a.len(),
                v => v.to_string().len(),
            }
            .into()
        })
        .with_function("is_empty", |_, v| {
            match &v[0] {
                Variable::String(s) => s.is_empty(),
                Variable::StringRef(s) => s.is_empty(),
                Variable::Integer(_) | Variable::Float(_) => false,
                Variable::Array(a) => a.is_empty(),
                Variable::ArrayRef(a) => a.is_empty(),
            }
            .into()
        })
        .with_function("is_ascii", |_, v| {
            match &v[0] {
                Variable::String(s) => s.chars().all(|c| c.is_ascii()),
                Variable::StringRef(s) => s.chars().all(|c| c.is_ascii()),
                Variable::Integer(_) | Variable::Float(_) => true,
                Variable::Array(a) => a.iter().all(|v| match v {
                    Variable::String(s) => s.chars().all(|c| c.is_ascii()),
                    Variable::StringRef(s) => s.chars().all(|c| c.is_ascii()),
                    _ => true,
                }),
                Variable::ArrayRef(a) => a.iter().all(|v| match v {
                    Variable::String(s) => s.chars().all(|c| c.is_ascii()),
                    Variable::StringRef(s) => s.chars().all(|c| c.is_ascii()),
                    _ => true,
                }),
            }
            .into()
        })
        .with_function("to_lowercase", |_, v| {
            v[0].to_cow().to_lowercase().to_string().into()
        })
        .with_function("to_uppercase", |_, v| {
            v[0].to_cow().to_uppercase().to_string().into()
        })
        .with_function("detect_language", |_, v| {
            whatlang::detect_lang(v[0].to_cow().as_ref())
                .map(|l| l.code())
                .unwrap_or("unknown")
                .into()
        })
        .with_function("is_email", |_, v| {
            is_email_valid(v[0].to_cow().as_ref()).into()
        })
        .with_function("domain_part", |_, v| {
            v[0].transform(|s| s.rsplit_once('@').map(|(_, d)| d.trim()))
        })
        .with_function("local_part", |_, v| {
            v[0].transform(|s| s.rsplit_once('@').map(|(u, _)| u.trim()))
        })
        .with_function("domain_name_part", |_, v| {
            v[0].transform(|s| {
                s.rsplit_once('@')
                    .and_then(|(_, d)| d.trim().split('.').rev().nth(1))
            })
        })
        .with_function("subdomain_part", |_, v| {
            v[0].to_cow()
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
        .with_function("thread_name", |_, v| {
            v[0].transform(|s| thread_name(s).into())
        })
        .with_function("html_to_text", |_, v| {
            html_to_text(v[0].to_cow().as_ref()).into()
        })
        .with_function("is_uppercase", |_, v| {
            v[0].to_cow()
                .as_ref()
                .chars()
                .filter(|c| c.is_alphabetic())
                .all(|c| c.is_uppercase())
                .into()
        })
        .with_function("is_lowercase", |_, v| {
            v[0].to_cow()
                .as_ref()
                .chars()
                .filter(|c| c.is_alphabetic())
                .all(|c| c.is_lowercase())
                .into()
        })
        .with_function("tokenize_words", |_, v| {
            match &v[0] {
                Variable::StringRef(s) => s
                    .split_whitespace()
                    .filter(|word| word.chars().all(|c| c.is_alphanumeric()))
                    .map(Variable::from)
                    .collect::<Vec<_>>(),
                Variable::String(s) => s
                    .split_whitespace()
                    .filter(|word| word.chars().all(|c| c.is_alphanumeric()))
                    .map(|word| Variable::from(word.to_string()))
                    .collect::<Vec<_>>(),
                v => v
                    .to_string()
                    .split_whitespace()
                    .filter(|word| word.chars().all(|c| c.is_alphanumeric()))
                    .map(|word| Variable::from(word.to_string()))
                    .collect::<Vec<_>>(),
            }
            .into()
        })
        .with_function("max_line_len", |_, v| {
            match &v[0] {
                Variable::String(s) => s.lines().map(|l| l.len()).max().unwrap_or(0),
                Variable::StringRef(s) => s.lines().map(|l| l.len()).max().unwrap_or(0),
                Variable::Integer(_) | Variable::Float(_) => 0,
                Variable::Array(a) => a.iter().map(|v| v.to_cow().len()).max().unwrap_or(0),
                Variable::ArrayRef(a) => a.iter().map(|v| v.to_cow().len()).max().unwrap_or(0),
            }
            .into()
        })
        .with_function("count_spaces", |_, v| {
            v[0].to_cow()
                .as_ref()
                .chars()
                .filter(|c| c.is_whitespace())
                .count()
                .into()
        })
        .with_function("count_uppercase", |_, v| {
            v[0].to_cow()
                .as_ref()
                .chars()
                .filter(|c| c.is_alphabetic() && c.is_uppercase())
                .count()
                .into()
        })
        .with_function("count_lowercase", |_, v| {
            v[0].to_cow()
                .as_ref()
                .chars()
                .filter(|c| c.is_alphabetic() && c.is_lowercase())
                .count()
                .into()
        })
        .with_function("count_chars", |_, v| {
            v[0].to_cow().as_ref().chars().count().into()
        })
        .with_function("count_control_chars", |_, v| {
            v[0].to_cow()
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
        .with_function_args(
            "eq_ignore_case",
            |_, v| {
                v[0].to_cow()
                    .eq_ignore_ascii_case(v[1].to_cow().as_ref())
                    .into()
            },
            2,
        )
        .with_function_args(
            "received_part",
            |ctx, v| {
                if let (Ok(part), Some(HeaderValue::Received(rcvd))) = (
                    ReceivedPart::try_from(v[1].to_cow().as_ref()),
                    ctx.message()
                        .part(ctx.part())
                        .and_then(|p| {
                            p.headers
                                .iter()
                                .filter(|h| h.name == HeaderName::Received)
                                .nth((v[0].to_integer() as usize).saturating_sub(1))
                        })
                        .map(|h| &h.value),
                ) {
                    part.eval(rcvd).unwrap_or_default()
                } else {
                    Variable::default()
                }
            },
            2,
        )
        .with_function_args(
            "cosine_similarity",
            |_, v| {
                let mut word_freq: HashMap<Cow<str>, [u32; 2]> = HashMap::new();

                for (idx, var) in v.into_iter().enumerate() {
                    match var {
                        Variable::Array(l) => {
                            for item in l {
                                word_freq.entry(item.into_cow()).or_insert([0, 0])[idx] += 1;
                            }
                        }
                        Variable::ArrayRef(l) => {
                            for item in l {
                                word_freq.entry(item.to_cow()).or_insert([0, 0])[idx] += 1;
                            }
                        }
                        _ => {
                            for char in var.to_cow().chars() {
                                word_freq.entry(char.to_string().into()).or_insert([0, 0])[idx] +=
                                    1;
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
            },
            2,
        )
        .with_function_args(
            "jaccard_similarity",
            |_, v| {
                let mut word_freq = [HashSet::new(), HashSet::new()];

                for (idx, var) in v.into_iter().enumerate() {
                    match var {
                        Variable::Array(l) => {
                            for item in l {
                                word_freq[idx].insert(item.into_cow());
                            }
                        }
                        Variable::ArrayRef(l) => {
                            for item in l {
                                word_freq[idx].insert(item.to_cow());
                            }
                        }
                        _ => {
                            for char in var.to_cow().chars() {
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
            },
            2,
        )
        .with_function_no_args("var_names", |ctx, _| {
            Variable::Array(
                ctx.global_variable_names()
                    .map(|v| Variable::from(v.to_string()))
                    .collect(),
            )
        })
        .with_function_no_args("is_encoding_problem", |ctx, _| {
            ctx.message()
                .part(ctx.part())
                .map(|p| p.is_encoding_problem)
                .unwrap_or_default()
                .into()
        })
        .with_function_no_args("is_attachment", |ctx, _| {
            ctx.message().attachments.contains(&ctx.part()).into()
        })
        .with_function_no_args("is_body", |ctx, _| {
            (ctx.message().text_body.contains(&ctx.part())
                || ctx.message().html_body.contains(&ctx.part()))
            .into()
        })
        .with_function_no_args("attachment_name", |ctx, _| {
            ctx.message()
                .part(ctx.part())
                .and_then(|p| p.attachment_name())
                .unwrap_or_default()
                .into()
        })
}

trait ApplyString<'x> {
    fn transform(&self, f: impl Fn(&str) -> Option<&str>) -> Variable<'x>;
    fn transform_string<T: Into<Variable<'x>>>(
        &self,
        f: impl Fn(&str) -> T,
    ) -> Option<Variable<'x>>;
}

impl<'x> ApplyString<'x> for Variable<'x> {
    fn transform(&self, f: impl Fn(&str) -> Option<&str>) -> Variable<'x> {
        match self {
            Variable::String(s) => {
                f(s).map_or(Variable::default(), |s| Variable::from(s.to_string()))
            }
            Variable::StringRef(s) => f(s).map_or(Variable::default(), Variable::from),
            v => f(v.to_string().as_str())
                .map_or(Variable::default(), |s| Variable::from(s.to_string())),
        }
    }

    fn transform_string<T: Into<Variable<'x>>>(
        &self,
        f: impl Fn(&str) -> T,
    ) -> Option<Variable<'x>> {
        match self {
            Variable::String(s) => Some(f(s).into()),
            Variable::StringRef(s) => Some(f(s).into()),
            Variable::Integer(_)
            | Variable::Float(_)
            | Variable::Array(_)
            | Variable::ArrayRef(_) => None,
        }
    }
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
