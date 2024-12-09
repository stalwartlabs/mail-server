use std::future::Future;

use common::Server;
use mail_auth::{
    common::verify::VerifySignature, dmarc::Policy, DkimResult, DmarcResult, SpfResult,
};

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeDmarc: Sync + Send {
    fn spam_filter_analyze_dmarc(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeDmarc for Server {
    async fn spam_filter_analyze_dmarc(&self, ctx: &mut SpamFilterContext<'_>) {
        ctx.result
            .add_tag(match ctx.input.spf_mail_from_result.result() {
                SpfResult::Pass => "SPF_ALLOW",
                SpfResult::Fail => "SPF_FAIL",
                SpfResult::SoftFail => "SPF_SOFTFAIL",
                SpfResult::Neutral => "SPF_NEUTRAL",
                SpfResult::TempError => "SPF_DNSFAIL",
                SpfResult::PermError => "SPF_PERMFAIL",
                SpfResult::None => "SPF_NA",
            });

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

        ctx.result.add_tag(match ctx.input.arc_result.result() {
            DkimResult::Pass => "ARC_ALLOW",
            DkimResult::Fail(_) => "ARC_REJECT",
            DkimResult::PermError(_) => "ARC_INVALID",
            DkimResult::TempError(_) => "ARC_DNSFAIL",
            DkimResult::Neutral(_) | DkimResult::None => "ARC_NA",
        });

        ctx.result.add_tag(match ctx.input.dmarc_result {
            DmarcResult::Pass => "DMARC_POLICY_ALLOW",
            DmarcResult::TempError(_) => "DMARC_DNSFAIL",
            DmarcResult::PermError(_) => "DMARC_BAD_POLICY",
            DmarcResult::None => "DMARC_NA",
            DmarcResult::Fail(_) => match ctx.input.dmarc_policy {
                Policy::Quarantine => "DMARC_POLICY_QUARANTINE",
                Policy::Reject => "DMARC_POLICY_REJECT",
                Policy::Unspecified | Policy::None => "DMARC_POLICY_SOFTFAIL",
            },
        });

        for header in ctx.input.message.headers() {
            let header_name = header.name();
            if header_name.eq_ignore_ascii_case("DKIM-Signature") {
                ctx.result.add_tag("DKIM_SIGNED");
            } else if header_name.eq_ignore_ascii_case("ARC-Seal") {
                ctx.result.add_tag("ARC_SIGNED");
            }
        }

        if self
            .core
            .spam
            .list_dmarc_allow
            .contains(&ctx.output.from.email.domain_part.fqdn)
        {
            if matches!(ctx.input.dmarc_result, DmarcResult::Pass) {
                ctx.result.add_tag("ALLOWLIST_DMARC");
            } else {
                ctx.result.add_tag("BLOCKLIST_DMARC");
            }
        } else if self
            .core
            .spam
            .list_spf_dkim_allow
            .contains(&ctx.output.from.email.domain_part.fqdn)
        {
            let is_dkim_pass = matches!(ctx.input.arc_result.result(), DkimResult::Pass)
                || ctx.input.dkim_result.iter().any(|r| {
                    matches!(r.result(), DkimResult::Pass)
                        && r.signature().map_or(false, |s| {
                            s.domain().to_lowercase() == ctx.output.from.email.domain_part.fqdn
                        })
                });
            let is_spf_pass = matches!(ctx.input.spf_mail_from_result.result(), SpfResult::Pass);

            if is_dkim_pass && is_spf_pass {
                ctx.result.add_tag("ALLOWLIST_SPF_DKIM");
            } else if is_dkim_pass {
                ctx.result.add_tag("ALLOWLIST_DKIM");
                if !matches!(
                    ctx.input.spf_mail_from_result.result(),
                    SpfResult::TempError
                ) {
                    ctx.result.add_tag("BLOCKLIST_SPF");
                }
            } else if is_spf_pass {
                ctx.result.add_tag("ALLOWLIST_SPF");
                if !ctx
                    .input
                    .dkim_result
                    .iter()
                    .any(|r| matches!(r.result(), DkimResult::TempError(_)))
                {
                    ctx.result.add_tag("BLOCKLIST_DKIM");
                }
            } else if !matches!(
                ctx.input.spf_mail_from_result.result(),
                SpfResult::TempError
            ) && !ctx
                .input
                .dkim_result
                .iter()
                .any(|r| matches!(r.result(), DkimResult::TempError(_)))
            {
                ctx.result.add_tag("BLOCKLIST_SPF_DKIM");
            }
        }
    }
}
