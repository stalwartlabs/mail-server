/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod array;
mod email;
mod header;
pub mod html;
mod image;
mod misc;
pub mod text;
mod unicode;
mod url;

use sieve::{runtime::Variable, FunctionMap};

use self::{
    array::*, email::*, header::*, html::*, image::*, misc::*, text::*, unicode::*, url::*,
};

pub fn register_functions() -> FunctionMap {
    FunctionMap::new()
        .with_function("trim", fn_trim)
        .with_function("trim_start", fn_trim_start)
        .with_function("trim_end", fn_trim_end)
        .with_function("len", fn_len)
        .with_function("count", fn_count)
        .with_function("is_empty", fn_is_empty)
        .with_function("is_number", fn_is_number)
        .with_function("is_ascii", fn_is_ascii)
        .with_function("to_lowercase", fn_to_lowercase)
        .with_function("to_uppercase", fn_to_uppercase)
        .with_function("detect_language", fn_detect_language)
        .with_function("is_email", fn_is_email)
        .with_function("thread_name", fn_thread_name)
        .with_function("html_to_text", fn_html_to_text)
        .with_function("is_uppercase", fn_is_uppercase)
        .with_function("is_lowercase", fn_is_lowercase)
        .with_function("has_digits", fn_has_digits)
        .with_function("count_spaces", fn_count_spaces)
        .with_function("count_uppercase", fn_count_uppercase)
        .with_function("count_lowercase", fn_count_lowercase)
        .with_function("count_chars", fn_count_chars)
        .with_function("dedup", fn_dedup)
        .with_function("lines", fn_lines)
        .with_function("is_header_utf8_valid", fn_is_header_utf8_valid)
        .with_function("img_metadata", fn_img_metadata)
        .with_function("is_ip_addr", fn_is_ip_addr)
        .with_function("is_ipv4_addr", fn_is_ipv4_addr)
        .with_function("is_ipv6_addr", fn_is_ipv6_addr)
        .with_function("ip_reverse_name", fn_ip_reverse_name)
        .with_function("winnow", fn_winnow)
        .with_function("has_zwsp", fn_has_zwsp)
        .with_function("has_obscured", fn_has_obscured)
        .with_function("is_single_script", fn_is_single_script)
        .with_function("puny_decode", fn_puny_decode)
        .with_function("unicode_skeleton", fn_unicode_skeleton)
        .with_function("cure_text", fn_cure_text)
        .with_function("detect_file_type", fn_detect_file_type)
        .with_function_args("sort", fn_sort, 2)
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
        .with_function_args("html_attrs", fn_html_attrs, 3)
        .with_function_args("html_attr_size", fn_html_attr_size, 3)
        .with_function_args("uri_part", fn_uri_part, 2)
        .with_function_args("substring", fn_substring, 3)
        .with_function_args("split", fn_split, 2)
        .with_function_args("rsplit", fn_rsplit, 2)
        .with_function_args("split_once", fn_split_once, 2)
        .with_function_args("rsplit_once", fn_rsplit_once, 2)
        .with_function_args("strip_prefix", fn_strip_prefix, 2)
        .with_function_args("strip_suffix", fn_strip_suffix, 2)
        .with_function_args("is_intersect", fn_is_intersect, 2)
        .with_function_args("hash", fn_hash, 2)
        .with_function_no_args("is_encoding_problem", fn_is_encoding_problem)
        .with_function_no_args("is_attachment", fn_is_attachment)
        .with_function_no_args("is_body", fn_is_body)
        .with_function_no_args("var_names", fn_is_var_names)
        .with_function_no_args("attachment_name", fn_attachment_name)
        .with_function_no_args("mime_part_len", fn_mime_part_len)
}

pub trait ApplyString<'x> {
    fn transform(&self, f: impl Fn(&'_ str) -> Variable) -> Variable;
}

impl<'x> ApplyString<'x> for Variable {
    fn transform(&self, f: impl Fn(&'_ str) -> Variable) -> Variable {
        match self {
            Variable::String(s) => f(s),
            Variable::Array(list) => list
                .iter()
                .map(|v| match v {
                    Variable::String(s) => f(s),
                    v => f(v.to_string().as_ref()),
                })
                .collect::<Vec<_>>()
                .into(),
            v => f(v.to_string().as_ref()),
        }
    }
}
