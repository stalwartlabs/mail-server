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

mod array;
mod email;
mod header;
pub mod html;
mod image;
mod text;

use sieve::{runtime::Variable, Context, FunctionMap};

use self::{array::*, email::*, header::*, html::*, image::*, text::*};

pub fn register_functions() -> FunctionMap {
    FunctionMap::new()
        .with_function("trim", fn_trim)
        .with_function("len", fn_len)
        .with_function("count", fn_count)
        .with_function("is_empty", fn_is_empty)
        .with_function("is_ascii", fn_is_ascii)
        .with_function("to_lowercase", fn_to_lowercase)
        .with_function("to_uppercase", fn_to_uppercase)
        .with_function("detect_language", fn_detect_language)
        .with_function("is_email", fn_is_email_valid)
        .with_function("thread_name", fn_thread_name)
        .with_function("html_to_text", fn_html_to_text)
        .with_function("is_uppercase", fn_is_uppercase)
        .with_function("is_lowercase", fn_is_lowercase)
        .with_function("tokenize_words", fn_tokenize_words)
        .with_function("tokenize_html", fn_tokenize_html)
        .with_function("max_line_len", fn_max_line_len)
        .with_function("count_spaces", fn_count_spaces)
        .with_function("count_uppercase", fn_count_uppercase)
        .with_function("count_lowercase", fn_count_lowercase)
        .with_function("count_chars", fn_count_chars)
        .with_function("dedup", fn_dedup)
        .with_function("lines", fn_lines)
        .with_function("is_header_utf8_valid", fn_is_header_utf8_valid)
        .with_function("img_metadata", fn_img_metadata)
        .with_function("sort", fn_sort)
        .with_function_args("email_part", fn_email_part, 2)
        .with_function_args("eq_ignore_case", fn_eq_ignore_case, 2)
        .with_function_args("contains", fn_contains, 2)
        .with_function_args("contains_ignore_case", fn_contains_ignore_case, 2)
        .with_function_args("starts_with", fn_starts_with, 2)
        .with_function_args("ends_with", fn_ends_with, 2)
        .with_function_args("received_part", fn_received_part, 2)
        .with_function_args("cosine_similarity", fn_cosine_similarity, 2)
        .with_function_args("jaccard_similarity", fn_jaccard_similarity, 2)
        .with_function_args("levenshtein_distance", fn_levenshtein_distance, 2)
        .with_function_args("html_has_tag", fn_html_has_tag, 2)
        .with_function_args("html_attr", fn_html_attr, 2)
        .with_function_args("html_attr_int", fn_html_attr_int, 3)
        .with_function_args("uri_part", fn_uri_part, 2)
        .with_function_args("substring", fn_substring, 3)
        .with_function_args("split", fn_split, 2)
        .with_function_no_args("is_encoding_problem", fn_is_encoding_problem)
        .with_function_no_args("is_attachment", fn_is_attachment)
        .with_function_no_args("is_body", fn_is_body)
        .with_function_no_args("var_names", fn_is_var_names)
        .with_function_no_args("attachment_name", fn_attachment_name)
}

pub fn fn_is_empty<'x>(_: &'x Context<'x>, v: Vec<Variable<'x>>) -> Variable<'x> {
    match &v[0] {
        Variable::String(s) => s.is_empty(),
        Variable::StringRef(s) => s.is_empty(),
        Variable::Integer(_) | Variable::Float(_) => false,
        Variable::Array(a) => a.is_empty(),
        Variable::ArrayRef(a) => a.is_empty(),
    }
    .into()
}

pub fn fn_is_var_names<'x>(ctx: &'x Context<'x>, _: Vec<Variable<'x>>) -> Variable<'x> {
    Variable::Array(
        ctx.global_variable_names()
            .map(|v| Variable::from(v.to_string()))
            .collect(),
    )
}

pub trait ApplyString<'x> {
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
