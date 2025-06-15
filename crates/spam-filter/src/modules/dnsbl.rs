/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};

use common::{
    Server,
    config::spamfilter::{DnsBlServer, Element, IpResolver, Location},
    expr::functions::ResolveVariable,
};
use compact_str::CompactString;
use mail_auth::{Error, common::resolver::IntoFqdn};
use trc::SpamEvent;

use crate::SpamFilterContext;

use super::expression::SpamFilterResolver;

pub(crate) async fn check_dnsbl(
    server: &Server,
    ctx: &mut SpamFilterContext<'_>,
    resolver: &impl ResolveVariable,
    scope: Element,
    location: Location,
) {
    let (mut checks, max_checks) = match scope {
        Element::Email => (
            ctx.result.rbl_email_checks,
            server.core.spam.dnsbl.max_email_checks,
        ),
        Element::Ip => (
            ctx.result.rbl_ip_checks,
            server.core.spam.dnsbl.max_ip_checks,
        ),
        Element::Url => (
            ctx.result.rbl_url_checks,
            server.core.spam.dnsbl.max_url_checks,
        ),
        Element::Domain => (
            ctx.result.rbl_domain_checks,
            server.core.spam.dnsbl.max_domain_checks,
        ),
        Element::Header | Element::Body | Element::Any => unreachable!(),
    };

    for dnsbl in &server.core.spam.dnsbl.servers {
        if dnsbl.scope == scope && checks < max_checks {
            if let Some(tag) = is_dnsbl(
                server,
                dnsbl,
                SpamFilterResolver::new(ctx, resolver, location),
                scope,
                &mut checks,
            )
            .await
            {
                ctx.result.add_tag(tag);
            }
        }
    }

    match scope {
        Element::Email => ctx.result.rbl_email_checks = checks,
        Element::Ip => ctx.result.rbl_ip_checks = checks,
        Element::Url => ctx.result.rbl_url_checks = checks,
        Element::Domain => ctx.result.rbl_domain_checks = checks,
        Element::Header | Element::Body | Element::Any => unreachable!(),
    }
}

async fn is_dnsbl(
    server: &Server,
    config: &DnsBlServer,
    resolver: SpamFilterResolver<'_, impl ResolveVariable>,
    element: Element,
    checks: &mut usize,
) -> Option<CompactString> {
    let time = Instant::now();
    let zone = server
        .eval_if::<CompactString, _>(&config.zone, &resolver, resolver.ctx.input.span_id)
        .await?;

    #[cfg(feature = "test_mode")]
    {
        if zone.contains(".11.20.") {
            let parts = zone.split('.').collect::<Vec<_>>();

            return if config.tags.if_then.iter().any(|i| i.expr.items.len() == 3) && parts[0] != "2"
            {
                None
            } else {
                server
                    .eval_if(
                        &config.tags,
                        &SpamFilterResolver::new(
                            resolver.ctx,
                            &IpResolver::new(
                                format!("127.0.{}.{}", parts[1], parts[0]).parse().unwrap(),
                            ),
                            resolver.location,
                        ),
                        resolver.ctx.input.span_id,
                    )
                    .await
            };
        }
    }

    let result = match server.inner.cache.dns_rbl.get(zone.as_str()) {
        Some(Some(result)) => result,
        Some(None) => return None,
        None => {
            *checks += 1;

            match server
                .core
                .smtp
                .resolvers
                .dns
                .ipv4_lookup_raw((&zone).into_fqdn().as_ref())
                .await
            {
                Ok(result) => {
                    trc::event!(
                        Spam(SpamEvent::Dnsbl),
                        Hostname = zone.clone(),
                        Result = result
                            .entry
                            .iter()
                            .map(|ip| trc::Value::from(ip.to_string()))
                            .collect::<Vec<_>>(),
                        Details = element.as_str(),
                        Elapsed = time.elapsed()
                    );

                    let entry = Arc::new(IpResolver::new(
                        result
                            .entry
                            .iter()
                            .copied()
                            .next()
                            .unwrap_or(Ipv4Addr::BROADCAST)
                            .into(),
                    ));

                    server.inner.cache.dns_rbl.insert_with_expiry(
                        zone.to_string(),
                        Some(entry.clone()),
                        result.expires,
                    );

                    entry
                }
                Err(Error::DnsRecordNotFound(_)) => {
                    trc::event!(
                        Spam(SpamEvent::Dnsbl),
                        Hostname = zone.clone(),
                        Result = trc::Value::None,
                        Details = element.as_str(),
                        Elapsed = time.elapsed()
                    );

                    server.inner.cache.dns_rbl.insert(
                        zone.to_string(),
                        None,
                        Duration::from_secs(86400),
                    );

                    return None;
                }
                Err(err) => {
                    trc::event!(
                        Spam(SpamEvent::DnsblError),
                        Hostname = zone,
                        Elapsed = time.elapsed(),
                        Details = element.as_str(),
                        CausedBy = err.to_string()
                    );

                    return None;
                }
            }
        }
    };

    server
        .eval_if(
            &config.tags,
            &SpamFilterResolver::new(resolver.ctx, result.as_ref(), resolver.location),
            resolver.ctx.input.span_id,
        )
        .await
}
