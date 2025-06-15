/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use compact_str::CompactString;
use mail_auth::common::resolver::ToReverseName;

use crate::expr::Variable;

pub(crate) fn fn_is_empty(v: Vec<Variable>) -> Variable {
    match &v[0] {
        Variable::String(s) => s.is_empty(),
        Variable::Integer(_) | Variable::Float(_) => false,
        Variable::Array(a) => a.is_empty(),
    }
    .into()
}

pub(crate) fn fn_is_number(v: Vec<Variable>) -> Variable {
    matches!(&v[0], Variable::Integer(_) | Variable::Float(_)).into()
}

pub(crate) fn fn_is_ip_addr(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_str()
        .parse::<std::net::IpAddr>()
        .is_ok()
        .into()
}

pub(crate) fn fn_is_ipv4_addr(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_str()
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| matches!(ip, IpAddr::V4(_)))
        .into()
}

pub(crate) fn fn_is_ipv6_addr(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_str()
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| matches!(ip, IpAddr::V6(_)))
        .into()
}

pub(crate) fn fn_ip_reverse_name(v: Vec<Variable>) -> Variable {
    CompactString::new(
        v[0].to_string()
            .as_str()
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.to_reverse_name())
            .unwrap_or_default(),
    )
    .into()
}

pub(crate) fn fn_if_then(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let condition = v.next().unwrap();
    let iff = v.next().unwrap();
    let then = v.next().unwrap();

    if condition.to_bool() { iff } else { then }
}
