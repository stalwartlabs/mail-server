/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::Server;

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeEhlo: Sync + Send {
    fn spam_filter_analyze_ehlo(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeEhlo for Server {
    async fn spam_filter_analyze_ehlo(&self, ctx: &mut SpamFilterContext<'_>) {
        if let Some(ehlo_ip) = ctx.output.ehlo_host.ip {
            // Helo host is bare ip
            ctx.result.add_tag("HELO_BAREIP");

            if ehlo_ip != ctx.input.remote_ip {
                // Helo A IP != hostname IP
                ctx.result.add_tag("HELO_IP_A");
            }
        } else if ctx.output.ehlo_host.sld.is_some() {
            if ctx
                .output
                .iprev_ptr
                .as_ref()
                .is_some_and(|ptr| ptr != ctx.output.ehlo_host.fqdn)
            {
                // Helo does not match reverse IP
                ctx.result.add_tag("HELO_IPREV_MISMATCH");
            }

            if matches!(
                (
                    self.dns_exists_ip(&ctx.output.ehlo_host.fqdn).await,
                    self.dns_exists_mx(&ctx.output.ehlo_host.fqdn).await
                ),
                (Ok(false), Ok(false))
            ) {
                // Helo no resolve to A or MX
                ctx.result.add_tag("HELO_NORES_A_OR_MX");
            }
        } else {
            if ctx.output.ehlo_host.fqdn.contains("user") {
                // Helo host contains 'user'
                ctx.result.add_tag("RCVD_HELO_USER");
            }

            // Helo not FQDN
            ctx.result.add_tag("HELO_NOT_FQDN");
        }
    }
}
