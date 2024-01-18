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

use crate::expr::Variable;

pub(crate) fn fn_is_email(v: Vec<Variable>) -> Variable {
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

pub(crate) fn fn_email_part(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap();
    let part = v.next().unwrap().into_string();

    value.transform(|s| match s {
        Cow::Borrowed(s) => s
            .rsplit_once('@')
            .map(|(u, d)| match part.as_ref() {
                "local" => Variable::from(u.trim()),
                "domain" => Variable::from(d.trim()),
                _ => Variable::default(),
            })
            .unwrap_or_default(),
        Cow::Owned(s) => s
            .rsplit_once('@')
            .map(|(u, d)| match part.as_ref() {
                "local" => Variable::from(u.trim().to_string()),
                "domain" => Variable::from(d.trim().to_string()),
                _ => Variable::default(),
            })
            .unwrap_or_default(),
    })
}
