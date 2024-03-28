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
