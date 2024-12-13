use std::future::Future;

use common::Server;
use mail_auth::DmarcResult;
use store::{Deserialize, Serialize};

use crate::{
    modules::{key_get, key_set},
    SpamFilterContext,
};

pub trait SpamFilterAnalyzeReputation: Sync + Send {
    fn spam_filter_analyze_reputation(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

enum Type {
    Ip,
    From,
    Domain,
    Asn,
}

#[derive(Debug)]
struct Reputation {
    count: u32,
    score: f64,
}

impl SpamFilterAnalyzeReputation for Server {
    async fn spam_filter_analyze_reputation(&self, ctx: &mut SpamFilterContext<'_>) {
        // Obtain sender address
        let sender = if !ctx.output.env_from_addr.address.is_empty() {
            &ctx.output.env_from_addr
        } else {
            &ctx.output.from.email
        };

        // Do not penalize forged domains
        let prefix = if matches!(ctx.input.dmarc_result, DmarcResult::Pass) {
            ""
        } else {
            "_"
        };

        let mut types = vec![
            (Type::Ip, format!("i:{}", ctx.input.remote_ip)),
            (Type::From, format!("f:{}{}", prefix, sender.address)),
            (
                Type::Domain,
                format!("d:{}{}", prefix, sender.domain_part.sld_or_default()),
            ),
        ];

        // Add ASN
        if let Some(asn_id) = &ctx.input.asn {
            ctx.result.add_tag(format!("SOURCE_ASN_{asn_id}"));
            types.push((Type::Asn, format!("a:{asn_id}")));
        }

        if let Some(country) = &ctx.input.country {
            ctx.result.add_tag(format!("SOURCE_COUNTRY_{country}"));
        }

        if let Some(config) = &self.core.spam.reputation {
            let mut reputation = 0.0;

            for (rep_type, key) in types {
                let key = key.into_bytes();

                let mut token =
                    match key_get::<Reputation>(self, ctx.input.span_id, key.clone()).await {
                        Ok(Some(token)) => token,
                        Ok(None) if !ctx.input.is_test => {
                            key_set(
                                self,
                                ctx.input.span_id,
                                key,
                                Reputation {
                                    count: 1,
                                    score: ctx.result.score,
                                }
                                .serialize(),
                                config.expiry.into(),
                            )
                            .await;
                            continue;
                        }
                        _ => continue,
                    };

                // Update reputation
                token.score = (token.count + 1) as f64
                    * (ctx.result.score + config.token_score * token.score)
                    / (config.token_score * token.count as f64 + 1.0);
                token.count += 1;
                if !ctx.input.is_test {
                    key_set(
                        self,
                        ctx.input.span_id,
                        key,
                        token.serialize(),
                        config.expiry.into(),
                    )
                    .await;
                }

                // Assign weight
                let weight = match rep_type {
                    Type::Ip => config.ip_weight,
                    Type::From => config.sender_weight,
                    Type::Domain => config.domain_weight,
                    Type::Asn => config.asn_weight,
                };

                reputation += token.score / token.count as f64 * weight;
            }

            // Adjust score
            if reputation > 0.0 {
                ctx.result.score += (reputation - ctx.result.score) * config.factor;
            }
        }
    }
}

impl Serialize for &Reputation {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&self.count.to_be_bytes());
        buf.extend_from_slice(&self.score.to_be_bytes());
        buf
    }
}

impl Deserialize for Reputation {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        if bytes.len() == 12 {
            Ok(Reputation {
                count: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                score: f64::from_be_bytes([
                    bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10],
                    bytes[11],
                ]),
            })
        } else {
            Err(trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes))
        }
    }
}

impl From<store::Value<'_>> for Reputation {
    fn from(_: store::Value<'_>) -> Self {
        unimplemented!()
    }
}
