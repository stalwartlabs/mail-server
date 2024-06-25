/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use sieve::{runtime::Variable, Context};

use super::ApplyString;

pub fn fn_is_email<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    let mut last_ch = 0;
    let mut in_quote = false;
    let mut at_count = 0;
    let mut dot_count = 0;
    let mut lp_len = 0;
    let mut value = 0;

    for ch in v[0].to_string().bytes() {
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
                    return false.into();
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
                    return false.into();
                }
            }
        }

        last_ch = ch;
    }

    (at_count == 1 && dot_count > 0 && lp_len > 0 && value > 0).into()
}

pub fn fn_email_part<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    v[0].transform(|s| {
        s.rsplit_once('@')
            .map(|(u, d)| match v[1].to_string().as_ref() {
                "local" => Variable::from(u.trim()),
                "domain" => Variable::from(d.trim()),
                _ => Variable::default(),
            })
            .unwrap_or_default()
    })
}
