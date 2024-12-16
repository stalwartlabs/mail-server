/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use std::future::Future;

use common::Server;

use crate::{modules::pyzor::pyzor_check, SpamFilterContext};

pub trait SpamFilterAnalyzePyzor: Sync + Send {
    fn spam_filter_analyze_pyzor(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzePyzor for Server {
    async fn spam_filter_analyze_pyzor(&self, ctx: &mut SpamFilterContext<'_>) {
        if let Some(config) = &self.core.spam.pyzor {
            match pyzor_check(ctx.input.message, config).await {
                Ok(Some(result)) => {
                    if result.code == 200
                        && result.count > config.min_count
                        && (result.wl_count < config.min_wl_count
                            || (result.wl_count as f64 / result.count as f64) < config.ratio)
                    {
                        ctx.result.add_tag("PYZOR");
                    }
                    let todo = "log time";
                }
                Ok(None) => {}
                Err(err) => {
                    trc::error!(err.span_id(ctx.input.span_id));
                }
            }
        }
    }
}
