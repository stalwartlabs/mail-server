use std::future::Future;

use common::Core;
use mail_auth::IprevResult;

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeIpRev: Sync + Send {
    fn spam_filter_analyze_iprev(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeIpRev for Core {
    async fn spam_filter_analyze_iprev(&self, ctx: &mut SpamFilterContext<'_>) {
        match &ctx.input.iprev_result.result {
            IprevResult::TempError(_) => ctx.result.add_tag("RDNS_DNSFAIL"),
            IprevResult::Fail(_) | IprevResult::PermError(_) => ctx.result.add_tag("RDNS_DNSFAIL"),
            IprevResult::Pass | IprevResult::None => (),
        }
    }
}
