/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use nlp::tokenizers::types::{TokenType, TypesTokenizer};
use sieve::{FunctionMap, runtime::Variable};

use crate::scripts::functions::{ApplyString, text::tokenize_words};

use super::PluginContext;

pub fn register_tokenize(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("tokenize", plugin_id, 2);
}

pub fn register_domain_part(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("domain_part", plugin_id, 2);
}

pub fn exec_tokenize(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let mut v = ctx.arguments;
    let (urls, urls_without_scheme, emails) = match v[1].to_string().as_ref() {
        "words" => return Ok(tokenize_words(&v[0])),
        "uri" | "url" => (true, true, true),
        "uri_strict" | "url_strict" => (true, false, false),
        "email" => (false, false, true),
        _ => return Ok(Variable::default()),
    };

    Ok(match v.remove(0) {
        v @ (Variable::String(_) | Variable::Array(_)) => {
            TypesTokenizer::new(v.to_string().as_ref())
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
    })
}

enum DomainPart {
    Sld,
    Tld,
    Host,
}

pub fn exec_domain_part(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let v = ctx.arguments;
    let part = match v[1].to_string().as_ref() {
        "sld" => DomainPart::Sld,
        "tld" => DomainPart::Tld,
        "host" => DomainPart::Host,
        _ => return Ok(Variable::default()),
    };

    Ok(v[0].transform(|domain| {
        match part {
            DomainPart::Sld => psl::domain_str(domain),
            DomainPart::Tld => domain.rsplit_once('.').map(|(_, tld)| tld),
            DomainPart::Host => domain.split_once('.').map(|(host, _)| host),
        }
        .map(Variable::from)
        .unwrap_or_default()
    }))
}
