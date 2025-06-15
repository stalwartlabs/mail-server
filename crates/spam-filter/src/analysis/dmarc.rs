/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::Server;
use mail_auth::{DkimResult, DmarcResult, SpfResult, dmarc::Policy};

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeDmarc: Sync + Send {
    fn spam_filter_analyze_dmarc(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeDmarc for Server {
    async fn spam_filter_analyze_dmarc(&self, ctx: &mut SpamFilterContext<'_>) {
        ctx.result.add_tag(
            ctx.input
                .spf_mail_from_result
                .map_or("SPF_NA", |r| match r.result() {
                    SpfResult::Pass => "SPF_ALLOW",
                    SpfResult::Fail => "SPF_FAIL",
                    SpfResult::SoftFail => "SPF_SOFTFAIL",
                    SpfResult::Neutral => "SPF_NEUTRAL",
                    SpfResult::TempError => "SPF_DNSFAIL",
                    SpfResult::PermError => "SPF_PERMFAIL",
                    SpfResult::None => "SPF_NA",
                }),
        );

        ctx.result.add_tag(
            match ctx
                .input
                .dkim_result
                .iter()
                .find(|r| matches!(r.result(), DkimResult::Pass))
                .or_else(|| ctx.input.dkim_result.first())
                .map(|r| r.result())
                .unwrap_or(&DkimResult::None)
            {
                DkimResult::Pass => "DKIM_ALLOW",
                DkimResult::Fail(_) => "DKIM_REJECT",
                DkimResult::PermError(_) => "DKIM_PERMFAIL",
                DkimResult::TempError(_) => "DKIM_TEMPFAIL",
                DkimResult::Neutral(_) | DkimResult::None => "DKIM_NA",
            },
        );

        ctx.result
            .add_tag(ctx.input.arc_result.map_or("ARC_NA", |r| match r.result() {
                DkimResult::Pass => "ARC_ALLOW",
                DkimResult::Fail(_) => "ARC_REJECT",
                DkimResult::PermError(_) => "ARC_INVALID",
                DkimResult::TempError(_) => "ARC_DNSFAIL",
                DkimResult::Neutral(_) | DkimResult::None => "ARC_NA",
            }));

        ctx.result
            .add_tag(ctx.input.dmarc_result.map_or("DMARC_NA", |r| match r {
                DmarcResult::Pass => "DMARC_POLICY_ALLOW",
                DmarcResult::TempError(_) => "DMARC_DNSFAIL",
                DmarcResult::PermError(_) => "DMARC_BAD_POLICY",
                DmarcResult::None => "DMARC_NA",
                DmarcResult::Fail(_) => ctx.input.dmarc_policy.map_or(
                    "DMARC_POLICY_SOFTFAIL",
                    |p| match p {
                        Policy::Quarantine => "DMARC_POLICY_QUARANTINE",
                        Policy::Reject => "DMARC_POLICY_REJECT",
                        Policy::Unspecified | Policy::None => "DMARC_POLICY_SOFTFAIL",
                    },
                ),
            }));
    }
}
