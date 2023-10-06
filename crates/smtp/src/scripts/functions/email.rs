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

use sieve::{runtime::Variable, Context};

use crate::config::scripts::SieveContext;

use super::ApplyString;

pub fn fn_is_email<'x>(_: &'x Context<'x, SieveContext>, v: Vec<Variable<'x>>) -> Variable<'x> {
    let mut last_ch = 0;
    let mut in_quote = false;
    let mut at_count = 0;
    let mut dot_count = 0;
    let mut lp_len = 0;
    let mut value = 0;

    for ch in v[0].to_cow().bytes() {
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

pub fn fn_email_part<'x>(_: &'x Context<'x, SieveContext>, v: Vec<Variable<'x>>) -> Variable<'x> {
    v[0].transform(|s| {
        s.rsplit_once('@')
            .map(|(u, d)| match v[1].to_cow().as_ref() {
                "local" => Variable::StringRef(u.trim()),
                "domain" => Variable::StringRef(d.trim()),
                _ => Variable::default(),
            })
            .unwrap_or_default()
    })
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum MatchPart {
    Sld,
    Tld,
    Host,
}

pub fn fn_domain_part<'x>(
    ctx: &'x Context<'x, SieveContext>,
    v: Vec<Variable<'x>>,
) -> Variable<'x> {
    let match_part = match v[1].to_cow().as_ref() {
        "sld" => MatchPart::Sld,
        "tld" => MatchPart::Tld,
        "host" => MatchPart::Host,
        _ => return Variable::default(),
    };

    v[0].transform(|domain| {
        let d = domain.trim().to_lowercase();
        let mut seen_dot = false;
        for (pos, ch) in d.as_bytes().iter().enumerate().rev() {
            if *ch == b'.' {
                if seen_dot {
                    let maybe_domain =
                        std::str::from_utf8(&d.as_bytes()[pos + 1..]).unwrap_or_default();
                    if !ctx.context().psl.contains(maybe_domain) {
                        return if match_part == MatchPart::Sld {
                            maybe_domain
                        } else {
                            std::str::from_utf8(&d.as_bytes()[..pos]).unwrap_or_default()
                        }
                        .to_string()
                        .into();
                    }
                } else if match_part == MatchPart::Tld {
                    return std::str::from_utf8(&d.as_bytes()[pos + 1..])
                        .unwrap_or_default()
                        .to_string()
                        .into();
                } else {
                    seen_dot = true;
                }
            }
        }

        if seen_dot {
            if match_part == MatchPart::Sld {
                d.into()
            } else {
                Variable::default()
            }
        } else if match_part == MatchPart::Host {
            d.into()
        } else {
            Variable::default()
        }
    })
}
