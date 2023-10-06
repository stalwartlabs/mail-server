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

use std::net::IpAddr;

use hyper::Uri;
use linkify::LinkKind;
use sieve::{runtime::Variable, Context};

use crate::config::scripts::SieveContext;

use super::ApplyString;

pub fn tokenize_url<'x>(
    ctx: &'x Context<'x, SieveContext>,
    v: Variable<'x>,
    must_have_scheme: bool,
) -> Variable<'x> {
    match v {
        Variable::StringRef(text) => linkify::LinkFinder::new()
            .url_must_have_scheme(must_have_scheme)
            .kinds(&[LinkKind::Url])
            .links(text.as_ref())
            .filter_map(|url| filter_url(url.as_str(), must_have_scheme, ctx))
            .collect::<Vec<_>>()
            .into(),
        v @ (Variable::String(_) | Variable::Array(_) | Variable::ArrayRef(_)) => {
            linkify::LinkFinder::new()
                .url_must_have_scheme(must_have_scheme)
                .kinds(&[LinkKind::Url])
                .links(v.to_cow().as_ref())
                .filter_map(|url| {
                    filter_url(url.as_str(), must_have_scheme, ctx).map(|v| v.into_owned())
                })
                .collect::<Vec<_>>()
                .into()
        }
        v => v,
    }
}

pub fn tokenize_email(v: Variable<'_>) -> Variable<'_> {
    match v {
        Variable::StringRef(text) => linkify::LinkFinder::new()
            .email_domain_must_have_dot(true)
            .kinds(&[LinkKind::Email])
            .links(text.as_ref())
            .map(|email| Variable::StringRef(email.as_str()))
            .collect::<Vec<_>>()
            .into(),
        v @ (Variable::String(_) | Variable::Array(_) | Variable::ArrayRef(_)) => {
            linkify::LinkFinder::new()
                .email_domain_must_have_dot(true)
                .kinds(&[LinkKind::Email])
                .links(v.to_cow().as_ref())
                .map(|email| Variable::String(email.as_str().to_string()))
                .collect::<Vec<_>>()
                .into()
        }
        v => v,
    }
}

fn filter_url<'x, 'y>(
    url: &'x str,
    must_have_scheme: bool,
    ctx: &'y Context<'y, SieveContext>,
) -> Option<Variable<'x>> {
    if must_have_scheme || url.contains("://") {
        Some(Variable::StringRef(url))
    } else {
        // Filter out possible URLs without a valid TLD
        let host = url.split_once('/').map_or(url, |(f, _)| f);
        if (host
            .as_bytes()
            .first()
            .map_or(true, |ch| ch.is_ascii_hexdigit())
            && host.parse::<IpAddr>().is_ok())
            || ctx
                .context()
                .psl
                .contains(host.rsplit_once('.').map_or(host, |(_, tld)| tld))
            || host.ends_with(".onion")
        {
            Some(Variable::String(format!("https://{url}")))
        } else {
            None
        }
    }
}

pub fn fn_uri_part<'x>(_: &'x Context<'x, SieveContext>, v: Vec<Variable<'x>>) -> Variable<'x> {
    let part = v[1].to_cow();
    v[0].transform(|uri| {
        uri.parse::<Uri>()
            .ok()
            .and_then(|uri| match part.as_ref() {
                "scheme" => uri.scheme_str().map(|s| Variable::String(s.to_string())),
                "host" => uri.host().map(|s| Variable::String(s.to_string())),
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
    })
}

pub fn fn_puny_decode<'x>(_: &'x Context<'x, SieveContext>, v: Vec<Variable<'x>>) -> Variable<'x> {
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
