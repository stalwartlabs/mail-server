/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, future::Future};

use common::{
    KV_REPUTATION_ASN, KV_REPUTATION_DOMAIN, KV_REPUTATION_FROM, KV_REPUTATION_IP, Server,
    ip_to_bytes,
};
use mail_auth::DmarcResult;
use store::{Deserialize, Serialize, dispatch::lookup::KeyValue};

use crate::{
    SpamFilterContext,
    modules::{key_get, key_set},
};

pub trait SpamFilterAnalyzeReputation: Sync + Send {
    fn spam_filter_analyze_reputation(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

#[derive(Debug)]
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
        let is_dmarc_pass = matches!(ctx.input.dmarc_result, Some(DmarcResult::Pass));

        let mut types = vec![
            (Type::Ip, Cow::Owned(ip_to_bytes(&ctx.input.remote_ip))),
            (
                Type::From,
                if is_dmarc_pass {
                    Cow::Borrowed(sender.address.as_bytes())
                } else {
                    Cow::Owned(format!("_{}", sender.domain_part.sld_or_default()).into_bytes())
                },
            ),
            (
                Type::Domain,
                if is_dmarc_pass {
                    Cow::Borrowed(sender.domain_part.sld_or_default().as_bytes())
                } else {
                    Cow::Owned(format!("_{}", sender.domain_part.sld_or_default()).into_bytes())
                },
            ),
        ];

        // Add ASN
        if let Some(asn_id) = &ctx.input.asn {
            ctx.result.add_tag(format!("SOURCE_ASN_{asn_id}"));
            types.push((Type::Asn, Cow::Owned(asn_id.to_be_bytes().to_vec())));
        }

        if let Some(country) = &ctx.input.country {
            ctx.result.add_tag(format!("SOURCE_COUNTRY_{country}"));
        }

        if let Some(config) = &self.core.spam.reputation {
            let mut reputation = 0.0;

            for (rep_type, key) in types {
                let token = match key_get::<Reputation>(
                    self,
                    ctx.input.span_id,
                    KeyValue::<()>::build_key(rep_type.prefix(), key.as_ref()),
                )
                .await
                {
                    Ok(Some(token)) => token,
                    Ok(None) if !ctx.input.is_test => {
                        key_set(
                            self,
                            ctx.input.span_id,
                            KeyValue::with_prefix(
                                rep_type.prefix(),
                                key.as_ref(),
                                Reputation {
                                    count: 1,
                                    score: ctx.result.score,
                                }
                                .serialize()
                                .unwrap(),
                            )
                            .expires(config.expiry),
                        )
                        .await;
                        continue;
                    }
                    Ok(None) | Err(_) => continue,
                };

                // Update reputation
                let updated_score = (token.count + 1) as f64
                    * (ctx.result.score + config.token_score * token.score)
                    / (config.token_score * token.count as f64 + 1.0);
                let updated_count = token.count + 1;

                if !ctx.input.is_test {
                    key_set(
                        self,
                        ctx.input.span_id,
                        KeyValue::with_prefix(
                            rep_type.prefix(),
                            key.as_ref(),
                            Reputation {
                                count: updated_count,
                                score: updated_score,
                            }
                            .serialize()
                            .unwrap(),
                        )
                        .expires(config.expiry),
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

impl Type {
    pub fn prefix(&self) -> u8 {
        match self {
            Type::Ip => KV_REPUTATION_IP,
            Type::From => KV_REPUTATION_FROM,
            Type::Domain => KV_REPUTATION_DOMAIN,
            Type::Asn => KV_REPUTATION_ASN,
        }
    }
}

impl Serialize for Reputation {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&self.count.to_be_bytes());
        buf.extend_from_slice(&self.score.to_be_bytes());
        Ok(buf)
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
