/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::Server;
use mail_parser::HeaderName;
use store::write::now;

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeDate: Sync + Send {
    fn spam_filter_analyze_date(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeDate for Server {
    async fn spam_filter_analyze_date(&self, ctx: &mut SpamFilterContext<'_>) {
        match ctx
            .input
            .message
            .header(HeaderName::Date)
            .map(|h| h.as_datetime())
        {
            Some(Some(date)) => {
                let date = date.to_timestamp();
                if date != 0 {
                    let date_diff = now() as i64 - date;

                    if date_diff > 86400 {
                        // Older than a day
                        ctx.result.add_tag("DATE_IN_PAST");
                    } else if -date_diff > 7200 {
                        //# More than 2 hours in the future
                        ctx.result.add_tag("DATE_IN_FUTURE");
                    }
                } else {
                    ctx.result.add_tag("INVALID_DATE");
                }
            }
            Some(None) => {
                ctx.result.add_tag("INVALID_DATE");
            }

            None => {
                ctx.result.add_tag("MISSING_DATE");
            }
        }
    }
}
