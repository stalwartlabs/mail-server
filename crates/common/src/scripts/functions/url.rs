/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use hyper::Uri;
use sieve::{runtime::Variable, Context};

use super::ApplyString;

pub fn fn_uri_part<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    let part = v[1].to_string();
    v[0].transform(|uri| {
        uri.parse::<Uri>()
            .ok()
            .and_then(|uri| match part.as_ref() {
                "scheme" => uri.scheme_str().map(|s| Variable::from(s.to_string())),
                "host" => uri.host().map(|s| Variable::from(s.to_string())),
                "scheme_host" => uri
                    .scheme_str()
                    .and_then(|s| (s, uri.host()?).into())
                    .map(|(s, h)| Variable::from(format!("{}://{}", s, h))),
                "path" => Variable::from(uri.path().to_string()).into(),
                "port" => uri.port_u16().map(|port| Variable::Integer(port as i64)),
                "query" => uri.query().map(|s| Variable::from(s.to_string())),
                "path_query" => uri.path_and_query().map(|s| Variable::from(s.to_string())),
                "authority" => uri.authority().map(|s| Variable::from(s.to_string())),
                _ => None,
            })
            .unwrap_or_default()
    })
}

pub fn fn_puny_decode<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    v[0].transform(|domain| {
        if domain.contains("xn--") {
            let mut decoded = String::with_capacity(domain.len());
            for part in domain.split('.') {
                if !decoded.is_empty() {
                    decoded.push('.');
                }

                if let Some(puny) = part
                    .strip_prefix("xn--")
                    .and_then(idna::punycode::decode_to_string)
                {
                    decoded.push_str(&puny);
                } else {
                    decoded.push_str(part);
                }
            }
            decoded.into()
        } else {
            domain.into()
        }
    })
}
