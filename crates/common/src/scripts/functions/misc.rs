/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use mail_auth::common::resolver::ToReverseName;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sieve::{runtime::Variable, Context};

use super::ApplyString;

pub fn fn_is_empty<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    match &v[0] {
        Variable::String(s) => s.is_empty(),
        Variable::Integer(_) | Variable::Float(_) => false,
        Variable::Array(a) => a.is_empty(),
    }
    .into()
}

pub fn fn_is_number<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    matches!(&v[0], Variable::Integer(_) | Variable::Float(_)).into()
}

pub fn fn_is_ip_addr<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    v[0].to_string().parse::<std::net::IpAddr>().is_ok().into()
}

pub fn fn_is_ipv4_addr<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .parse::<std::net::IpAddr>()
        .map_or(false, |ip| matches!(ip, IpAddr::V4(_)))
        .into()
}

pub fn fn_is_ipv6_addr<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .parse::<std::net::IpAddr>()
        .map_or(false, |ip| matches!(ip, IpAddr::V6(_)))
        .into()
}

pub fn fn_ip_reverse_name<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.to_reverse_name())
        .unwrap_or_default()
        .into()
}

pub fn fn_detect_file_type<'x>(ctx: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    ctx.message()
        .part(ctx.part())
        .and_then(|p| infer::get(p.contents()))
        .map(|t| {
            Variable::from(
                if v[0].to_string() != "ext" {
                    t.mime_type()
                } else {
                    t.extension()
                }
                .to_string(),
            )
        })
        .unwrap_or_default()
}

pub fn fn_hash<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    use sha1::Digest;
    let hash = v[1].to_string();

    v[0].transform(|value| match hash.as_ref() {
        "md5" => format!("{:x}", md5::compute(value.as_bytes())).into(),
        "sha1" => {
            let mut hasher = Sha1::new();
            hasher.update(value.as_bytes());
            format!("{:x}", hasher.finalize()).into()
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            format!("{:x}", hasher.finalize()).into()
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(value.as_bytes());
            format!("{:x}", hasher.finalize()).into()
        }
        _ => Variable::default(),
    })
}

pub fn fn_is_var_names<'x>(ctx: &'x Context<'x>, _: Vec<Variable>) -> Variable {
    Variable::Array(
        ctx.global_variable_names()
            .map(|v| Variable::from(v.to_uppercase()))
            .collect::<Vec<_>>()
            .into(),
    )
}
