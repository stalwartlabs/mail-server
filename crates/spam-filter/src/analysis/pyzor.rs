/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{future::Future, time::Instant};

use common::Server;

use crate::{SpamFilterContext, modules::pyzor::pyzor_check};

pub trait SpamFilterAnalyzePyzor: Sync + Send {
    fn spam_filter_analyze_pyzor(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzePyzor for Server {
    async fn spam_filter_analyze_pyzor(&self, ctx: &mut SpamFilterContext<'_>) {
        if let Some(config) = &self.core.spam.pyzor {
            let time = Instant::now();
            match pyzor_check(ctx.input.message, config).await {
                Ok(Some(result)) => {
                    let is_spam = result.code == 200
                        && result.count > config.min_count
                        && (result.wl_count < config.min_wl_count
                            || (result.wl_count as f64 / result.count as f64) < config.ratio);
                    if is_spam {
                        ctx.result.add_tag("PYZOR");
                    }
                    trc::event!(
                        Spam(trc::SpamEvent::Pyzor),
                        Result = is_spam,
                        Details = vec![
                            trc::Value::from(result.code),
                            trc::Value::from(result.count),
                            trc::Value::from(result.wl_count)
                        ],
                        SpanId = ctx.input.span_id,
                        Elapsed = time.elapsed()
                    );
                }
                Ok(None) => {}
                Err(err) => {
                    trc::error!(
                        err.span_id(ctx.input.span_id)
                            .ctx(trc::Key::Elapsed, time.elapsed())
                    );
                }
            }
        }
    }
}
