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
 * in the LICENSE file at the top-level store of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use nlp::tokenizers::types::{TokenType, TypesTokenizer};
use sieve::{runtime::Variable, FunctionMap};

use crate::scripts::functions::{html::html_to_tokens, text::tokenize_words, ApplyString};

use super::PluginContext;

#[derive(PartialEq, Eq, Clone, Copy)]
enum MatchPart {
    Sld,
    Tld,
    Host,
}

pub fn register_tokenize(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("tokenize", plugin_id, 2);
}

pub fn register_domain_part(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("domain_part", plugin_id, 2);
}

pub fn exec_tokenize(ctx: PluginContext<'_>) -> Variable {
    let mut v = ctx.arguments;
    let (urls, urls_without_scheme, emails) = match v[1].to_string().as_ref() {
        "html" => return html_to_tokens(v[0].to_string().as_ref()).into(),
        "words" => return tokenize_words(&v[0]),
        "uri" | "url" => (true, true, true),
        "uri_strict" | "url_strict" => (true, false, false),
        "email" => (false, false, true),
        _ => return Variable::default(),
    };

    match v.remove(0) {
        v @ (Variable::String(_) | Variable::Array(_)) => {
            TypesTokenizer::new(v.to_string().as_ref(), &ctx.core.smtp.resolvers.psl)
                .tokenize_numbers(false)
                .tokenize_urls(urls)
                .tokenize_urls_without_scheme(urls_without_scheme)
                .tokenize_emails(emails)
                .filter_map(|t| match t.word {
                    TokenType::Url(text) if urls => Variable::from(text.to_string()).into(),
                    TokenType::UrlNoScheme(text) if urls_without_scheme => {
                        Variable::from(format!("https://{text}")).into()
                    }
                    TokenType::Email(text) if emails => Variable::from(text.to_string()).into(),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .into()
        }
        v => v,
    }
}

pub fn exec_domain_part(ctx: PluginContext<'_>) -> Variable {
    let v = ctx.arguments;
    let match_part = match v[1].to_string().as_ref() {
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
                    if !ctx.core.smtp.resolvers.psl.contains(maybe_domain) {
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
