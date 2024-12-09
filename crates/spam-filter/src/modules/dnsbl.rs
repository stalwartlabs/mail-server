use std::time::Instant;

use common::{config::spamfilter::DnsblConfig, Server};
use mail_auth::Error;
use trc::SpamEvent;

pub async fn is_dnsbl(
    server: &Server,
    config: &DnsblConfig,
    item: &str,
    span_id: u64,
) -> Option<String> {
    let time = Instant::now();
    let zone = server
        .eval_expr::<String, _>(&config.zone, &item, &config.id, span_id)
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

            server.eval_if(&config.tags, &result, span_id).await
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
