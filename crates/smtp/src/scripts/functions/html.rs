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

use hyper::Uri;
use mail_parser::decoders::html::{add_html_token, html_to_text};
use sieve::{runtime::Variable, Context};

pub fn fn_html_to_text<'x>(_: &'x Context<'x>, v: Vec<Variable<'x>>) -> Variable<'x> {
    html_to_text(v[0].to_cow().as_ref()).into()
}

pub fn fn_tokenize_html<'x>(_: &'x Context<'x>, v: Vec<Variable<'x>>) -> Variable<'x> {
    html_to_tokens(v[0].to_cow().as_ref()).into()
}

pub fn fn_html_has_tag<'x>(_: &'x Context<'x>, v: Vec<Variable<'x>>) -> Variable<'x> {
    v[0].as_array()
        .map(|arr| {
            let token = v[1].to_cow();
            arr.iter().any(|v| {
                v.to_cow()
                    .as_ref()
                    .strip_prefix('<')
                    .map_or(false, |tag| tag.starts_with(token.as_ref()))
            })
        })
        .unwrap_or_default()
        .into()
}

pub fn fn_html_attr_size<'x>(_: &'x Context<'x>, v: Vec<Variable<'x>>) -> Variable<'x> {
    let t = v[0].to_cow();
    let mut dimension = None;

    if let Some(value) = get_attribute(t.as_ref(), v[1].to_cow().as_ref()) {
        let value = value.trim();
        if let Some(pct) = value.strip_suffix('%') {
            if let Ok(pct) = pct.trim().parse::<u32>() {
                dimension = ((v[2].to_integer() * pct as i64) / 100).into();
            }
        } else if let Ok(value) = value.parse::<u32>() {
            dimension = (value as i64).into();
        }
    }

    dimension.map(Variable::Integer).unwrap_or_default()
}

pub fn fn_html_attr<'x>(_: &'x Context<'x>, v: Vec<Variable<'x>>) -> Variable<'x> {
    get_attribute(v[0].to_cow().as_ref(), v[1].to_cow().as_ref())
        .map(|s| Variable::String(s.to_string()))
        .unwrap_or_default()
}

pub fn html_to_tokens(input: &str) -> Vec<Variable<'static>> {
    let input = input.as_bytes();
    let mut iter = input.iter().enumerate();
    let mut tags = vec![];

    let mut is_token_start = true;
    let mut is_after_space = false;
    let mut is_new_line = true;

    let mut token_start = 0;
    let mut token_end = 0;

    let mut text = String::from("_");

    while let Some((pos, &ch)) = iter.next() {
        match ch {
            b'<' => {
                if !is_token_start {
                    add_html_token(
                        &mut text,
                        &input[token_start..token_end + 1],
                        is_after_space,
                    );
                    is_after_space = false;
                    is_token_start = true;
                }
                if text.len() > 1 {
                    tags.push(Variable::String(text));
                    text = String::from("_");
                }

                let mut tag = vec![b'<'];
                if matches!(input.get(pos + 1..pos + 4), Some(b"!--")) {
                    let mut last_ch: u8 = 0;
                    for (_, &ch) in iter.by_ref() {
                        match ch {
                            b'>' if tag.len() > 3
                                && matches!(tag.last(), Some(b'-'))
                                && matches!(tag.get(tag.len() - 2), Some(b'-')) =>
                            {
                                break;
                            }
                            b' ' | b'\t' | b'\r' | b'\n' => {
                                if last_ch != b' ' {
                                    tag.push(b' ');
                                } else {
                                    last_ch = b' ';
                                }
                                continue;
                            }
                            _ => {
                                tag.push(ch);
                            }
                        }
                        last_ch = ch;
                    }
                } else {
                    let mut in_quote = false;
                    let mut last_ch = b' ';
                    for (_, &ch) in iter.by_ref() {
                        match ch {
                            b'>' if !in_quote => {
                                break;
                            }
                            b'"' => {
                                in_quote = !in_quote;
                                tag.push(b'"');
                            }
                            b' ' | b'\t' | b'\r' | b'\n' if !in_quote => {
                                if last_ch != b' ' {
                                    tag.push(b' ');
                                    last_ch = b' ';
                                }
                                continue;
                            }
                            b'/' if !in_quote => {
                                tag.push(b'/');
                                last_ch = b' ';
                                continue;
                            }
                            _ => {
                                tag.push(if in_quote {
                                    ch
                                } else {
                                    ch.to_ascii_lowercase()
                                });
                            }
                        }
                        last_ch = ch;
                    }
                }
                tags.push(Variable::String(String::from_utf8(tag).unwrap_or_default()));
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                if !is_token_start {
                    add_html_token(
                        &mut text,
                        &input[token_start..token_end + 1],
                        is_after_space && !is_new_line,
                    );
                    is_new_line = false;
                }
                is_after_space = true;
                is_token_start = true;
                continue;
            }
            b'&' if !is_token_start => {
                add_html_token(
                    &mut text,
                    &input[token_start..token_end + 1],
                    is_after_space && !is_new_line,
                );
                is_new_line = false;
                is_token_start = true;
                is_after_space = false;
            }
            b';' if !is_token_start => {
                add_html_token(
                    &mut text,
                    &input[token_start..pos + 1],
                    is_after_space && !is_new_line,
                );
                is_token_start = true;
                is_after_space = false;
                is_new_line = false;
                continue;
            }
            _ => (),
        }

        if is_token_start {
            token_start = pos;
            is_token_start = false;
        }
        token_end = pos;
    }

    if !is_token_start {
        add_html_token(
            &mut text,
            &input[token_start..token_end + 1],
            is_after_space && !is_new_line,
        );
    }
    if text.len() > 1 {
        tags.push(Variable::String(text));
    }

    tags
}

pub fn html_img_area(arr: &[Variable<'_>]) -> u32 {
    arr.iter()
        .filter_map(|v| {
            let t = v.to_cow();
            if t.starts_with("<img") {
                let mut dimensions = [200u32, 200u32];

                for (idx, attr) in ["width", "height"].into_iter().enumerate() {
                    if let Some(value) = get_attribute(t.as_ref(), attr) {
                        let value = value.trim();
                        if let Some(pct) = value.strip_suffix('%') {
                            if let Ok(pct) = pct.trim().parse::<u32>() {
                                let size = if idx == 0 { 800 } else { 600 };
                                dimensions[idx] = (size * pct) / 100;
                            }
                        } else if let Ok(value) = value.parse::<u32>() {
                            dimensions[idx] = value;
                        }
                    }
                }

                Some(dimensions[0].saturating_mul(dimensions[1]))
            } else {
                None
            }
        })
        .sum::<u32>()
}

pub fn fn_uri_part<'x>(_: &'x Context<'x>, v: Vec<Variable<'x>>) -> Variable<'x> {
    v[0].to_cow()
        .parse::<Uri>()
        .ok()
        .and_then(|uri| match v[1].to_cow().as_ref() {
            "scheme" => uri.scheme_str().map(|s| Variable::String(s.to_lowercase())),
            "host" => uri.host().map(|s| Variable::String(s.to_lowercase())),
            "scheme_host" => uri
                .scheme_str()
                .and_then(|s| (s, uri.host()?).into())
                .map(|(s, h)| Variable::String(format!("{}://{}", s, h))),
            "path" => Variable::String(uri.path().to_string()).into(),
            "port" => uri.port_u16().map(|port| Variable::Integer(port as i64)),
            "query" => uri.query().map(|s| Variable::String(s.to_string())),
            "path_query" => uri
                .path_and_query()
                .map(|s| Variable::String(s.to_string())),
            "authority" => uri.authority().map(|s| Variable::String(s.to_string())),
            _ => None,
        })
        .unwrap_or_default()
}

pub fn get_attribute<'x>(tag: &'x str, attr_name: &str) -> Option<&'x str> {
    let tag = tag.as_bytes();
    let attr_name = attr_name.as_bytes();
    let mut iter = tag.iter().enumerate().peekable();
    let mut in_quote = false;
    let mut start_pos = usize::MAX;
    let mut end_pos = usize::MAX;

    while let Some((pos, ch)) = iter.next() {
        match ch {
            b'=' if !in_quote => {
                if start_pos != usize::MAX
                    && end_pos != usize::MAX
                    && tag
                        .get(start_pos..end_pos + 1)
                        .map_or(false, |name| name == attr_name)
                {
                    let mut token_start = 0;
                    let mut token_end = 0;

                    for (pos, ch) in iter.by_ref() {
                        match ch {
                            b'"' => {
                                if !in_quote {
                                    token_start = pos + 1;
                                    in_quote = true;
                                } else {
                                    token_end = pos;
                                    break;
                                }
                            }
                            b' ' if !in_quote => {
                                if token_start != 0 {
                                    token_end = pos;
                                    break;
                                }
                            }
                            _ => {
                                if token_start == 0 {
                                    token_start = pos;
                                }
                            }
                        }
                    }

                    return if token_start > 0 {
                        if token_end == 0 {
                            token_end = tag.len();
                        }
                        Some(std::str::from_utf8(&tag[token_start..token_end]).unwrap_or_default())
                    } else {
                        None
                    };
                } else {
                    start_pos = usize::MAX;
                    end_pos = usize::MAX;
                }
            }
            b'"' => {
                in_quote = !in_quote;
            }
            b' ' => {
                if !in_quote && !matches!(iter.peek(), Some((_, b'='))) {
                    start_pos = usize::MAX;
                    end_pos = usize::MAX;
                }
            }
            _ => {
                if !in_quote {
                    if start_pos == usize::MAX {
                        start_pos = pos;
                    }
                    end_pos = pos;
                }
            }
        }
    }

    None
}
