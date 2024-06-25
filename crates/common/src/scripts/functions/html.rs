/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use mail_parser::decoders::html::{add_html_token, html_to_text};
use sieve::{runtime::Variable, Context};

pub fn fn_html_to_text<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    html_to_text(v[0].to_string().as_ref()).into()
}

pub fn fn_html_has_tag<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    v[0].as_array()
        .map(|arr| {
            let token = v[1].to_string();
            arr.iter().any(|v| {
                v.to_string()
                    .as_ref()
                    .strip_prefix('<')
                    .map_or(false, |tag| tag.starts_with(token.as_ref()))
            })
        })
        .unwrap_or_default()
        .into()
}

pub fn fn_html_attr_size<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    let t = v[0].to_string();
    let mut dimension = None;

    if let Some(value) = get_attribute(t.as_ref(), v[1].to_string().as_ref()) {
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

pub fn fn_html_attrs<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    html_attr_tokens(
        v[0].to_string().as_ref(),
        v[1].to_string().as_ref(),
        v[2].to_string_array(),
    )
    .into()
}

pub fn fn_html_attr<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    get_attribute(v[0].to_string().as_ref(), v[1].to_string().as_ref())
        .map(Variable::from)
        .unwrap_or_default()
}

pub fn html_to_tokens(input: &str) -> Vec<Variable> {
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
                    tags.push(Variable::String(text.into()));
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
                tags.push(Variable::String(
                    String::from_utf8(tag).unwrap_or_default().into(),
                ));
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
        tags.push(Variable::String(text.into()));
    }

    tags
}

pub fn html_attr_tokens(input: &str, tag: &str, attrs: Vec<Cow<str>>) -> Vec<Variable> {
    let input = input.as_bytes();
    let mut iter = input.iter().enumerate().peekable();
    let mut tags = vec![];

    while let Some((mut pos, &ch)) = iter.next() {
        if ch == b'<' {
            if !matches!(input.get(pos + 1..pos + 4), Some(b"!--")) {
                let mut in_quote = false;
                let mut last_ch_pos: usize = 0;

                while matches!(iter.peek(), Some((_, &ch)) if ch.is_ascii_whitespace()) {
                    pos += 1;
                    iter.next();
                }

                let found_tag = tag.is_empty()
                    || (matches!(input.get(pos + 1..pos + tag.len() + 1), Some(t) if t.eq_ignore_ascii_case(tag.as_bytes()))
                        && matches!(input.get(pos + tag.len() + 1), Some(ch) if ch.is_ascii_whitespace()));

                'outer: while let Some((pos, &ch)) = iter.next() {
                    match ch {
                        b'>' if !in_quote => {
                            break;
                        }
                        b'"' => {
                            in_quote = !in_quote;
                        }
                        b'=' if found_tag
                            && !in_quote
                            && attrs.iter().any(|attr| matches!(input.get(last_ch_pos.saturating_sub(attr.len()) + 1..last_ch_pos + 1), Some(a) if a.eq_ignore_ascii_case(attr.as_bytes())))
                            && matches!(input.get(last_ch_pos + 1), Some(ch) if ch.is_ascii_whitespace() || *ch == b'=') =>
                        {
                            while matches!(iter.peek(), Some((_, &ch)) if ch.is_ascii_whitespace())
                            {
                                iter.next();
                            }
                            let mut tag = vec![];

                            for (_, &ch) in iter.by_ref() {
                                match ch {
                                    b'>' if !in_quote => {
                                        if !tag.is_empty() {
                                            tags.push(Variable::String(
                                                String::from_utf8(tag).unwrap_or_default().into(),
                                            ));
                                        }
                                        break 'outer;
                                    }
                                    b'"' => {
                                        if in_quote {
                                            in_quote = false;
                                            break;
                                        } else {
                                            in_quote = true;
                                        }
                                    }
                                    b' ' | b'\t' | b'\r' | b'\n' if !in_quote => {
                                        break;
                                    }
                                    _ => {
                                        tag.push(ch);
                                    }
                                }
                            }

                            if !tag.is_empty() {
                                tags.push(Variable::String(
                                    String::from_utf8(tag).unwrap_or_default().into(),
                                ));
                            }
                        }
                        b' ' | b'\t' | b'\r' | b'\n' => {}
                        _ => {
                            last_ch_pos = pos;
                        }
                    }
                }
            } else {
                let mut last_ch: u8 = 0;
                let mut before_last_ch: u8 = 0;

                for (_, &ch) in iter.by_ref() {
                    if ch == b'>' && last_ch == b'-' && before_last_ch == b'-' {
                        break;
                    }
                    before_last_ch = last_ch;
                    last_ch = ch;
                }
            }
        }
    }

    tags
}

pub fn html_img_area(arr: &[Variable]) -> u32 {
    arr.iter()
        .filter_map(|v| {
            let t = v.to_string();
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
