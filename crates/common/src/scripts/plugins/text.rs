/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use nlp::tokenizers::types::{TokenType, TypesTokenizer};
use sieve::{runtime::Variable, FunctionMap};
use utils::suffixlist::DomainPart;

use crate::scripts::functions::{html::html_to_tokens, text::tokenize_words, ApplyString};

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
        "html" => return Ok(html_to_tokens(v[0].to_string().as_ref()).into()),
        "words" => return Ok(tokenize_words(&v[0])),
        "uri" | "url" => (true, true, true),
        "uri_strict" | "url_strict" => (true, false, false),
        "email" => (false, false, true),
        _ => return Ok(Variable::default()),
    };

    Ok(match v.remove(0) {
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
    })
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
        ctx.core
            .smtp
            .resolvers
            .psl
            .domain_part(domain, part)
            .map(Variable::from)
            .unwrap_or_default()
    }))
}
