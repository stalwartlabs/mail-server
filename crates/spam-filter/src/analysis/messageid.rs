use std::future::Future;

use common::Core;
use mail_parser::HeaderName;

use crate::{Hostname, SpamFilterContext};

pub trait SpamFilterAnalyzeEhlo: Sync + Send {
    fn spam_filter_analyze_message_id(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeEhlo for Core {
    async fn spam_filter_analyze_message_id(&self, ctx: &mut SpamFilterContext<'_>) {
        let mid_raw = ctx
            .input
            .message
            .header_raw(HeaderName::MessageId)
            .unwrap_or_default()
            .trim();

        if !mid_raw.is_empty() {
            let mid = ctx
                .input
                .message
                .message_id()
                .unwrap_or_default()
                .to_lowercase();
            if let Some(mid_host) = mid.rsplit_once('@').map(|(_, host)| Hostname::new(host)) {
                if mid_host.ip.is_some() {
                    if mid_host.fqdn.starts_with('[') {
                        ctx.add_tag("MID_RHS_IP_LITERAL");
                    } else {
                        ctx.add_tag("MID_BARE_IP");
                    }
                } else if !mid_host.fqdn.contains('.') {
                    ctx.add_tag("MID_RHS_NOT_FQDN");
                } else if mid_host.fqdn.starts_with("www.") {
                    ctx.add_tag("MID_RHS_WWW");
                }

                if !mid_raw.is_ascii() || mid_raw.contains('(') || mid.starts_with('@') {
                    ctx.add_tag("INVALID_MSGID");
                }

                if mid_host.fqdn.len() > 255 {
                    ctx.add_tag("MID_RHS_TOO_LONG");
                }

                // From address present in Message-ID checks
                for sender in [&ctx.output.from_addr, &ctx.output.env_from_addr] {
                    if !sender.address.is_empty() {
                        if mid.contains(&sender.address) {
                            ctx.output.tags.insert("MID_CONTAINS_FROM".to_string());
                        } else if mid_host.fqdn == sender.domain_part.fqdn {
                            ctx.output.tags.insert("MID_RHS_MATCH_FROM".to_string());
                        } else if matches!((&mid_host.sld, &sender.domain_part.sld), (Some(mid_sld), Some(sender_sld)) if mid_sld == sender_sld)
                        {
                            ctx.output.tags.insert("MID_RHS_MATCH_FROMTLD".to_string());
                        }
                    }
                }

                // To/Cc addresses present in Message-ID checks
                for addr in &ctx.output.recipients {
                    if mid.contains(&addr.address) {
                        ctx.output.tags.insert("MID_CONTAINS_TO".to_string());
                    } else if mid_host.fqdn == addr.domain_part.fqdn {
                        ctx.output.tags.insert("MID_RHS_MATCH_TO".to_string());
                    }
                }
            } else {
                ctx.add_tag("INVALID_MSGID");
            }

            if !mid_raw.starts_with('<') || !mid_raw.ends_with('>') {
                ctx.add_tag("MID_MISSING_BRACKETS");
            }
        } else {
            ctx.add_tag("MISSING_MID");
        }
    }
}
