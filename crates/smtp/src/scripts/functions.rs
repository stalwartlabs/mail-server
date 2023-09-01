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
        .with_function("domain", |v| {
            v.to_cow()
                .rsplit_once('@')
                .map_or(Variable::default(), |(_, d)| d.trim().to_string().into())
        })
        .with_function("base_domain", |v| {
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
        .with_function("word_count", |v| {
            v.to_cow().as_ref().split_whitespace().count().into()
        })
}
