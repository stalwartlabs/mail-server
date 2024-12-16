/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use std::time::Instant;

use common::{config::spamfilter::DnsblConfig, expr::functions::ResolveVariable, Server};
use mail_auth::Error;
use trc::SpamEvent;

use crate::modules::expression::StringListResolver;

use super::expression::SpamFilterResolver;

pub(crate) async fn is_dnsbl(
    server: &Server,
    config: &DnsblConfig,
    resolver: SpamFilterResolver<'_, impl ResolveVariable>,
) -> Option<String> {
    let time = Instant::now();
    let zone = server
        .eval_if::<String, _>(&config.zone, &resolver, resolver.ctx.input.span_id)
        .await?;
    let todo = "use proper event error";

    match server.core.smtp.resolvers.dns.ipv4_lookup(&zone).await {
        Ok(result) => {
            let result = result.iter().map(|ip| ip.to_string()).collect::<Vec<_>>();

            trc::event!(
                Spam(SpamEvent::Classify),
                Result = result
                    .iter()
                    .map(|ip| trc::Value::from(ip.clone()))
                    .collect::<Vec<_>>(),
                Elapsed = time.elapsed()
            );

            server
                .eval_if(
                    &config.tags,
                    &StringListResolver(&result),
                    resolver.ctx.input.span_id,
                )
                .await
        }
        Err(Error::DnsRecordNotFound(_)) => {
            trc::event!(
                Spam(SpamEvent::Classify),
                Result = trc::Value::None,
                Elapsed = time.elapsed()
            );

            None
        }
        Err(err) => {
            trc::event!(
                Spam(SpamEvent::Classify),
                Elapsed = time.elapsed(),
                CausedBy = err.to_string()
            );

            None
        }
    }
}
