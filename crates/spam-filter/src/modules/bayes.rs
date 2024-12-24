/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::HashSet, future::Future};

use common::{ip_to_bytes, Server, KV_BAYES_MODEL_GLOBAL, KV_BAYES_MODEL_USER};
use mail_auth::DmarcResult;
use nlp::{
    bayes::{
        tokenize::{BayesInputToken, BayesTokenizer},
        BayesModel, TokenHash, Weights,
    },
    tokenizers::{
        osb::{Gram, OsbToken, OsbTokenizer},
        types::TokenType,
    },
};
use store::dispatch::lookup::KeyValue;
use trc::AddContext;

use crate::{SpamFilterContext, TextPart};

pub trait BayesClassifier {
    fn bayes_train(
        &self,
        ctx: &SpamFilterContext<'_>,
        is_spam: bool,
        is_train: bool,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn bayes_classify(
        &self,
        ctx: &SpamFilterContext<'_>,
    ) -> impl Future<Output = trc::Result<Option<f64>>> + Send;

    fn bayes_is_balanced(
        &self,
        ctx: &SpamFilterContext<'_>,
        learn_spam: bool,
    ) -> impl Future<Output = trc::Result<bool>> + Send;

    fn bayes_train_if_balanced(
        &self,
        ctx: &SpamFilterContext<'_>,
        learn_spam: bool,
    ) -> impl Future<Output = ()> + Send;
}

impl BayesClassifier for Server {
    async fn bayes_train(
        &self,
        ctx: &SpamFilterContext<'_>,
        is_spam: bool,
        is_train: bool,
    ) -> trc::Result<()> {
        // Train the model
        let mut model = BayesModel::default();

        // Train metadata tokens
        for token in ctx.spam_tokens() {
            model.train_token(TokenHash::from(Gram::Uni { t1: &token }), is_spam);
        }

        // Train the subject
        model.train(
            OsbTokenizer::new(
                BayesTokenizer::new(
                    &ctx.output.subject_thread,
                    ctx.output.subject_tokens.iter().filter_map(to_bayes_token),
                ),
                5,
            ),
            is_spam,
        );

        // Train the body
        match ctx
            .input
            .message
            .html_body
            .first()
            .or_else(|| ctx.input.message.text_body.first())
            .and_then(|idx| ctx.output.text_parts.get(*idx))
        {
            Some(TextPart::Html {
                text_body, tokens, ..
            }) => {
                model.train(
                    OsbTokenizer::new(
                        BayesTokenizer::new(
                            text_body,
                            tokens.iter().filter_map(to_bayes_token_owned),
                        ),
                        5,
                    ),
                    is_spam,
                );
            }
            Some(TextPart::Plain { text_body, tokens }) => {
                model.train(
                    OsbTokenizer::new(
                        BayesTokenizer::new(text_body, tokens.iter().filter_map(to_bayes_token)),
                        5,
                    ),
                    is_spam,
                );
            }
            _ => {}
        }

        if model.weights.is_empty() {
            trc::bail!(trc::SpamEvent::TrainError
                .into_err()
                .reason("No weights found"));
        }

        trc::event!(
            Spam(trc::SpamEvent::Train),
            SpanId = ctx.input.span_id,
            Details = is_spam,
            Total = model.weights.len(),
        );

        // Update weight and invalidate cache
        if is_train {
            let prefix = if ctx.input.account_id.is_none() {
                KV_BAYES_MODEL_GLOBAL
            } else {
                KV_BAYES_MODEL_USER
            };
            for (hash, weights) in model.weights {
                self.in_memory_store()
                    .counter_incr(KeyValue::new(
                        hash.serialize(prefix, ctx.input.account_id),
                        i64::from(weights),
                    ))
                    .await
                    .caused_by(trc::location!())?;
            }

            // Update training counts
            let weights = if is_spam {
                Weights { spam: 1, ham: 0 }
            } else {
                Weights { spam: 0, ham: 1 }
            };
            self.in_memory_store()
                .counter_incr(KeyValue::new(
                    TokenHash::serialize_index(prefix, ctx.input.account_id),
                    i64::from(weights),
                ))
                .await
                .caused_by(trc::location!())
                .map(|_| ())
        } else {
            //TODO: Implement untrain
            Ok(())
        }
    }

    async fn bayes_classify(&self, ctx: &SpamFilterContext<'_>) -> trc::Result<Option<f64>> {
        let classifier = if let Some(config) = &self.core.spam.bayes {
            &config.classifier
        } else {
            return Ok(None);
        };

        // Obtain training counts
        let prefix = if ctx.input.account_id.is_none() {
            KV_BAYES_MODEL_GLOBAL
        } else {
            KV_BAYES_MODEL_USER
        };
        let (spam_learns, ham_learns) = self
            .in_memory_store()
            .counter_get(TokenHash::serialize_index(prefix, ctx.input.account_id))
            .await
            .map(|w| {
                let w = Weights::from(w);
                (w.spam, w.ham)
            })?;

        // Make sure we have enough training data
        if spam_learns < classifier.min_learns || ham_learns < classifier.min_learns {
            trc::event!(
                Spam(trc::SpamEvent::ClassifyError),
                SpanId = ctx.input.span_id,
                AccountId = ctx.input.account_id,
                Reason = "Not enough training data",
                Details = vec![
                    trc::Value::from(spam_learns),
                    trc::Value::from(ham_learns),
                    trc::Value::from(classifier.min_learns)
                ],
            );
            return Ok(None);
        }

        // Classify the text
        let mut osb_tokens = Vec::new();

        // Classify metadata tokens
        for token in ctx.spam_tokens() {
            let weights = self
                .in_memory_store()
                .counter_get(
                    TokenHash::from(Gram::Uni { t1: &token })
                        .serialize(prefix, ctx.input.account_id),
                )
                .await
                .map(Weights::from)?;
            osb_tokens.push(OsbToken {
                inner: weights,
                idx: 1,
            });
        }

        // Classify the subject
        for token in OsbTokenizer::<_, TokenHash>::new(
            BayesTokenizer::new(
                &ctx.output.subject_thread,
                ctx.output.subject_tokens.iter().filter_map(to_bayes_token),
            ),
            5,
        ) {
            let weights = self
                .in_memory_store()
                .counter_get(token.inner.serialize(prefix, ctx.input.account_id))
                .await
                .map(Weights::from)?;
            osb_tokens.push(OsbToken {
                inner: weights,
                idx: token.idx,
            });
        }

        // Classify the body
        match ctx
            .input
            .message
            .html_body
            .first()
            .or_else(|| ctx.input.message.text_body.first())
            .and_then(|idx| ctx.output.text_parts.get(*idx))
        {
            Some(TextPart::Html {
                text_body, tokens, ..
            }) => {
                for token in OsbTokenizer::<_, TokenHash>::new(
                    BayesTokenizer::new(text_body, tokens.iter().filter_map(to_bayes_token_owned)),
                    5,
                ) {
                    let weights = self
                        .in_memory_store()
                        .counter_get(token.inner.serialize(prefix, ctx.input.account_id))
                        .await
                        .map(Weights::from)?;
                    osb_tokens.push(OsbToken {
                        inner: weights,
                        idx: token.idx,
                    });
                }
            }
            Some(TextPart::Plain { text_body, tokens }) => {
                for token in OsbTokenizer::<_, TokenHash>::new(
                    BayesTokenizer::new(text_body, tokens.iter().filter_map(to_bayes_token)),
                    5,
                ) {
                    let weights = self
                        .in_memory_store()
                        .counter_get(token.inner.serialize(prefix, ctx.input.account_id))
                        .await
                        .map(Weights::from)?;
                    osb_tokens.push(OsbToken {
                        inner: weights,
                        idx: token.idx,
                    });
                }
            }
            _ => {}
        }

        let result = classifier.classify(osb_tokens.into_iter(), ham_learns, spam_learns);

        trc::event!(
            Spam(trc::SpamEvent::Classify),
            SpanId = ctx.input.span_id,
            AccountId = ctx.input.account_id,
            Details = vec![
                trc::Value::from(spam_learns),
                trc::Value::from(ham_learns),
                trc::Value::from(classifier.min_learns)
            ],
            Result = result.map(trc::Value::from).unwrap_or_default()
        );

        Ok(result)
    }

    async fn bayes_is_balanced(
        &self,
        ctx: &SpamFilterContext<'_>,
        learn_spam: bool,
    ) -> trc::Result<bool> {
        let min_balance = self
            .core
            .spam
            .bayes
            .as_ref()
            .map_or(0.0, |c| c.classifier.min_balance);

        if min_balance == 0.0 {
            return Ok(true);
        }

        // Obtain training counts
        let prefix = if ctx.input.account_id.is_none() {
            KV_BAYES_MODEL_GLOBAL
        } else {
            KV_BAYES_MODEL_USER
        };
        let (spam_learns, ham_learns) = self
            .in_memory_store()
            .counter_get(TokenHash::serialize_index(prefix, ctx.input.account_id))
            .await
            .map(|w| {
                let w = Weights::from(w);
                (w.spam as f64, w.ham as f64)
            })?;

        let result = if spam_learns > 0.0 || ham_learns > 0.0 {
            if learn_spam {
                (spam_learns / (ham_learns + 1.0)) <= 1.0 / min_balance
            } else {
                (ham_learns / (spam_learns + 1.0)) <= 1.0 / min_balance
            }
        } else {
            true
        };

        trc::event!(
            Spam(trc::SpamEvent::TrainBalance),
            SpanId = ctx.input.span_id,
            Details = vec![
                trc::Value::from(learn_spam),
                trc::Value::from(min_balance),
                trc::Value::from(spam_learns),
                trc::Value::from(ham_learns),
            ],
            Result = result
        );

        Ok(result)
    }

    async fn bayes_train_if_balanced(&self, ctx: &SpamFilterContext<'_>, learn_spam: bool) {
        let err = match self.bayes_is_balanced(ctx, learn_spam).await {
            Ok(true) => match self.bayes_train(ctx, learn_spam, true).await {
                Ok(_) => {
                    return;
                }
                Err(err) => err,
            },
            Ok(false) => {
                return;
            }
            Err(err) => err,
        };

        if let Some(account_id) = ctx.input.account_id {
            trc::error!(err
                .span_id(ctx.input.span_id)
                .account_id(account_id)
                .caused_by(trc::location!()));
        } else {
            trc::error!(err.span_id(ctx.input.span_id).caused_by(trc::location!()));
        }
    }
}

const P_FROM_NAME: u8 = 0;
const P_FROM_EMAIL: u8 = 1;
const P_FROM_DOMAIN: u8 = 2;
const P_ASN: u8 = 3;
const P_REMOTE_IP: u8 = 4;

impl SpamFilterContext<'_> {
    pub fn spam_tokens(&self) -> HashSet<Vec<u8>> {
        let mut tokens = HashSet::new();
        if matches!(self.input.dmarc_result, Some(DmarcResult::Pass))
            || self.input.account_id.is_some()
        {
            for addr in [&self.output.env_from_addr, &self.output.from.email] {
                if !addr.address.is_empty() {
                    tokens.insert(add_prefix(P_FROM_EMAIL, addr.address.as_bytes()));
                    tokens.insert(add_prefix(
                        P_FROM_DOMAIN,
                        addr.domain_part.sld_or_default().as_bytes(),
                    ));
                }
            }
            if let Some(name) = &self.output.from.name {
                for name_part in name.split_whitespace() {
                    tokens.insert(add_prefix(P_FROM_NAME, name_part.to_lowercase().as_bytes()));
                }
            }
        }
        if let Some(asn) = self.input.asn {
            tokens.insert(add_prefix(P_ASN, &asn.to_be_bytes()));
        }
        if !self.input.remote_ip.is_loopback() {
            tokens.insert(add_prefix(P_REMOTE_IP, &ip_to_bytes(&self.input.remote_ip)));
        }
        tokens
    }
}

fn add_prefix(prefix: u8, key: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(key.len() + 1);
    buf.extend_from_slice(key);
    buf.push(prefix);
    buf
}

fn to_bayes_token(token: &TokenType<&str>) -> Option<BayesInputToken> {
    token.to_bayes_token()
}

fn to_bayes_token_owned(token: &TokenType<String>) -> Option<BayesInputToken> {
    token.to_bayes_token()
}
