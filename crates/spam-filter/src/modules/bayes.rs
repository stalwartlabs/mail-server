/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, collections::HashSet, future::Future, time::Duration};

use common::{KV_BAYES_MODEL_GLOBAL, KV_BAYES_MODEL_USER, Server, ip_to_bytes};
use mail_auth::DmarcResult;
use nlp::{
    bayes::{
        BayesModel, TokenHash, Weights,
        tokenize::{BayesInputToken, BayesTokenizer, symbols},
    },
    tokenizers::{
        osb::{Gram, OsbToken, OsbTokenizer},
        types::TokenType,
    },
};
use store::dispatch::lookup::KeyValue;
use trc::AddContext;
use utils::cache::TtlEntry;

use crate::{Email, IpParts, SpamFilterContext, TextPart, analysis::url::UrlParts};

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

    fn bayes_weights_for_token(
        &self,
        account_id: Option<u32>,
        token: TokenHash,
    ) -> impl Future<Output = trc::Result<Weights>> + Send;
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
            .and_then(|idx| ctx.output.text_parts.get(*idx as usize))
        {
            Some(TextPart::Html {
                text_body, tokens, ..
            }) => {
                model.train(
                    OsbTokenizer::new(
                        BayesTokenizer::new(text_body, tokens.iter().filter_map(to_bayes_token)),
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
            trc::bail!(
                trc::SpamEvent::TrainError
                    .into_err()
                    .reason("No weights found")
            );
        }

        trc::event!(
            Spam(trc::SpamEvent::Train),
            SpanId = ctx.input.span_id,
            Details = is_spam,
            Total = model.weights.len(),
        );

        // Update weight and invalidate cache
        if is_train {
            let (is_global, prefix) = if ctx.input.account_id.is_none() {
                (true, KV_BAYES_MODEL_GLOBAL)
            } else {
                (false, KV_BAYES_MODEL_USER)
            };
            for (hash, weights) in model.weights {
                self.in_memory_store()
                    .counter_incr(
                        KeyValue::new(
                            hash.serialize(prefix, ctx.input.account_id),
                            i64::from(weights),
                        ),
                        false,
                    )
                    .await
                    .caused_by(trc::location!())?;
                if is_global {
                    self.inner.cache.bayes.remove(&hash);
                }
            }
            if is_global {
                self.inner.cache.bayes.remove(&TokenHash::default());
            }

            // Update training counts
            let weights = if is_spam {
                Weights { spam: 1, ham: 0 }
            } else {
                Weights { spam: 0, ham: 1 }
            };
            self.in_memory_store()
                .counter_incr(
                    KeyValue::new(
                        TokenHash::default().serialize(prefix, ctx.input.account_id),
                        i64::from(weights),
                    ),
                    false,
                )
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
        let (spam_learns, ham_learns) = self
            .bayes_weights_for_token(ctx.input.account_id, TokenHash::default())
            .await
            .map(|w| (w.spam, w.ham))?;

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
                .bayes_weights_for_token(
                    ctx.input.account_id,
                    TokenHash::from(Gram::Uni { t1: &token }),
                )
                .await?;
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
                .bayes_weights_for_token(ctx.input.account_id, token.inner)
                .await?;
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
            .and_then(|idx| ctx.output.text_parts.get(*idx as usize))
        {
            Some(TextPart::Html {
                text_body, tokens, ..
            }) => {
                for token in OsbTokenizer::<_, TokenHash>::new(
                    BayesTokenizer::new(text_body, tokens.iter().filter_map(to_bayes_token)),
                    5,
                ) {
                    let weights = self
                        .bayes_weights_for_token(ctx.input.account_id, token.inner)
                        .await?;
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
                        .bayes_weights_for_token(ctx.input.account_id, token.inner)
                        .await?;
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
        let (spam_learns, ham_learns) = self
            .bayes_weights_for_token(ctx.input.account_id, TokenHash::default())
            .await
            .map(|w| (w.spam as f64, w.ham as f64))?;

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
            trc::error!(
                err.span_id(ctx.input.span_id)
                    .account_id(account_id)
                    .caused_by(trc::location!())
            );
        } else {
            trc::error!(err.span_id(ctx.input.span_id).caused_by(trc::location!()));
        }
    }

    async fn bayes_weights_for_token(
        &self,
        account_id: Option<u32>,
        token: TokenHash,
    ) -> trc::Result<Weights> {
        match account_id {
            None => {
                match self
                    .inner
                    .cache
                    .bayes
                    .get_value_or_guard_async(&token)
                    .await
                {
                    Ok(weights) => Ok(weights),
                    Err(guard) => {
                        let weights = self
                            .in_memory_store()
                            .counter_get(token.serialize_global(KV_BAYES_MODEL_GLOBAL))
                            .await?;
                        let expiry = if weights != 0 {
                            Duration::from_secs(3 * 60 * 60)
                        } else {
                            Duration::from_secs(60 * 60)
                        };
                        let weights = Weights::from(weights);
                        let _ = guard.insert(TtlEntry::new(weights, expiry));
                        Ok(weights)
                    }
                }
            }
            Some(account_id) => self
                .in_memory_store()
                .counter_get(token.serialize_account(KV_BAYES_MODEL_USER, account_id))
                .await
                .map(Weights::from),
        }
    }
}

const P_FROM_NAME: u8 = 0;
const P_FROM_EMAIL: u8 = 1;
const P_FROM_DOMAIN: u8 = 2;
const P_ASN: u8 = 3;
const P_REMOTE_IP: u8 = 4;
const P_INTEGER_POS: u8 = 5;
const P_INTEGER_NEG: u8 = 6;
const P_FLOAT_POS: u8 = 7;
const P_FLOAT_NEG: u8 = 8;
const P_BODY_URL: u8 = 9;
const P_BODY_IP: u8 = 10;
const P_BODY_EMAIL: u8 = 11;

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
                for name_part in name.to_lowercase().split_whitespace() {
                    tokens.insert(add_prefix(P_FROM_NAME, name_part.as_bytes()));
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

fn to_bayes_token(
    token: &TokenType<Cow<'_, str>, Email, UrlParts<'_>, IpParts<'_>>,
) -> Option<BayesInputToken> {
    match token {
        TokenType::Alphabetic(word) => Some(BayesInputToken::Word(word.as_ref().to_lowercase())),
        TokenType::Url(url) | TokenType::UrlNoScheme(url) => url.url_parsed.as_ref().map(|url| {
            BayesInputToken::Raw(add_prefix(P_BODY_URL, url.host.sld_or_default().as_bytes()))
        }),
        TokenType::IpAddr(ip) => ip
            .ip
            .as_ref()
            .map(|ip| BayesInputToken::Raw(add_prefix(P_BODY_IP, &ip_to_bytes(ip)))),
        TokenType::Alphanumeric(word) | TokenType::UrlNoHost(word) => {
            BayesInputToken::Raw(word.as_ref().to_lowercase().into_bytes()).into()
        }
        TokenType::Email(email) => BayesInputToken::Raw(add_prefix(
            P_BODY_EMAIL,
            email.domain_part.sld_or_default().as_bytes(),
        ))
        .into(),
        TokenType::Other(ch) => {
            let ch = ch.to_string();
            if symbols(&ch) {
                Some(BayesInputToken::Raw(ch.into_bytes()))
            } else {
                None
            }
        }
        TokenType::Integer(word) => number_to_tag(false, word.as_ref()).into(),
        TokenType::Float(word) => number_to_tag(true, word.as_ref()).into(),
        TokenType::Punctuation(_) | TokenType::Space => None,
    }
}

fn number_to_tag(is_float: bool, num: &str) -> BayesInputToken {
    let t = match (is_float, num.starts_with('-')) {
        (true, true) => P_FLOAT_NEG,
        (true, false) => P_FLOAT_POS,
        (false, true) => P_INTEGER_NEG,
        (false, false) => P_INTEGER_POS,
    };

    BayesInputToken::Raw([t, num.len() as u8].to_vec())
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.address
    }
}

impl AsRef<str> for UrlParts<'_> {
    fn as_ref(&self) -> &str {
        &self.url
    }
}

impl AsRef<str> for IpParts<'_> {
    fn as_ref(&self) -> &str {
        &self.text
    }
}
