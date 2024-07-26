/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use nlp::{
    bayes::{
        cache::BayesTokenCache, tokenize::BayesTokenizer, BayesClassifier, BayesModel, TokenHash,
        Weights,
    },
    tokenizers::osb::{OsbToken, OsbTokenizer},
};
use sieve::{runtime::Variable, FunctionMap};
use store::{write::key::KeySerializer, LookupStore, U64_LEN};
use trc::AddContext;

use super::PluginContext;

pub fn register_train(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("bayes_train", plugin_id, 3);
}

pub fn register_untrain(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("bayes_untrain", plugin_id, 3);
}

pub fn register_classify(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("bayes_classify", plugin_id, 3);
}

pub fn register_is_balanced(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("bayes_is_balanced", plugin_id, 3);
}

pub async fn exec_train(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    train(ctx, true).await
}

pub async fn exec_untrain(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    train(ctx, false).await
}

async fn train(ctx: PluginContext<'_>, is_train: bool) -> trc::Result<Variable> {
    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    }
    .ok_or_else(|| {
        trc::SieveEvent::RuntimeError
            .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
            .details("Unknown store")
    })?;

    let text = ctx.arguments[1].to_string();
    let is_spam = ctx.arguments[2].to_bool();
    if text.is_empty() {
        trc::bail!(trc::SpamEvent::TrainError
            .into_err()
            .reason("Empty message"));
    }

    // Train the model
    let mut model = BayesModel::default();
    model.train(
        OsbTokenizer::new(
            BayesTokenizer::new(text.as_ref(), &ctx.core.smtp.resolvers.psl),
            5,
        ),
        is_spam,
    );
    if model.weights.is_empty() {
        trc::bail!(trc::SpamEvent::TrainError
            .into_err()
            .reason("No weights found"));
    }

    trc::event!(
        Spam(trc::SpamEvent::Train),
        SpanId = ctx.session_id,
        Spam = is_spam,
        Size = model.weights.len(),
    );

    // Update weight and invalidate cache
    let bayes_cache = &ctx.cache.bayes_cache;
    if is_train {
        for (hash, weights) in model.weights {
            store
                .counter_incr(
                    KeySerializer::new(U64_LEN)
                        .write(hash.h1)
                        .write(hash.h2)
                        .finalize(),
                    weights.into(),
                    None,
                    false,
                )
                .await
                .caused_by(trc::location!())?;

            bayes_cache.invalidate(&hash);
        }

        // Update training counts
        let weights = if is_spam {
            Weights { spam: 1, ham: 0 }
        } else {
            Weights { spam: 0, ham: 1 }
        };
        store
            .counter_incr(
                KeySerializer::new(U64_LEN)
                    .write(0u64)
                    .write(0u64)
                    .finalize(),
                weights.into(),
                None,
                false,
            )
            .await
            .caused_by(trc::location!())?;
    } else {
        //TODO: Implement untrain
        return Ok(false.into());
    }

    bayes_cache.invalidate(&TokenHash::default());

    Ok(true.into())
}

pub async fn exec_classify(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    }
    .ok_or_else(|| {
        trc::SieveEvent::RuntimeError
            .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
            .details("Unknown store")
    })?;
    let text = ctx.arguments[1].to_string();
    if text.is_empty() {
        trc::bail!(trc::SpamEvent::ClassifyError
            .into_err()
            .reason("Empty message"));
    }

    // Create classifier from defaults
    let mut classifier = BayesClassifier::default();
    if let Some(params) = ctx.arguments[2].as_array() {
        if let Some(Variable::Integer(value)) = params.first() {
            classifier.min_token_hits = *value as u32;
        }
        if let Some(Variable::Integer(value)) = params.get(1) {
            classifier.min_tokens = *value as u32;
        }
        if let Some(Variable::Float(value)) = params.get(2) {
            classifier.min_prob_strength = *value;
        }
        if let Some(Variable::Integer(value)) = params.get(3) {
            classifier.min_learns = *value as u32;
        }
    }

    // Obtain training counts
    let bayes_cache = &ctx.cache.bayes_cache;
    let (spam_learns, ham_learns) = bayes_cache
        .get_or_update(TokenHash::default(), store)
        .await
        .map(|w| (w.spam, w.ham))?;

    // Make sure we have enough training data
    if spam_learns < classifier.min_learns || ham_learns < classifier.min_learns {
        trc::event!(
            Spam(trc::SpamEvent::NotEnoughTrainingData),
            SpanId = ctx.session_id,
            MinLearns = classifier.min_learns,
            SpamLearns = spam_learns,
            HamLearns = ham_learns
        );
        return Ok(Variable::default());
    }

    // Classify the text
    let mut tokens = Vec::new();
    for token in OsbTokenizer::<_, TokenHash>::new(
        BayesTokenizer::new(text.as_ref(), &ctx.core.smtp.resolvers.psl),
        5,
    ) {
        let weights = bayes_cache.get_or_update(token.inner, store).await?;
        tokens.push(OsbToken {
            inner: weights,
            idx: token.idx,
        });
    }
    let result = classifier.classify(tokens.into_iter(), ham_learns, spam_learns);

    trc::event!(
        Spam(trc::SpamEvent::Classify),
        SpanId = ctx.session_id,
        MinLearns = classifier.min_learns,
        SpamLearns = spam_learns,
        HamLearns = ham_learns,
        Result = result.unwrap_or_default()
    );

    Ok(result.map(Variable::from).unwrap_or_default())
}

pub async fn exec_is_balanced(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let min_balance = match &ctx.arguments[2] {
        Variable::Float(n) => *n,
        Variable::Integer(n) => *n as f64,
        _ => 0.0,
    };

    if min_balance == 0.0 {
        return Ok(true.into());
    }

    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    }
    .ok_or_else(|| {
        trc::SieveEvent::RuntimeError
            .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
            .details("Unknown store")
    })?;

    let learn_spam = ctx.arguments[1].to_bool();

    // Obtain training counts
    let bayes_cache = &ctx.cache.bayes_cache;
    let (spam_learns, ham_learns) = bayes_cache
        .get_or_update(TokenHash::default(), store)
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
        SpanId = ctx.session_id,
        Spam = learn_spam,
        MinBalance = min_balance,
        SpamLearns = spam_learns,
        HamLearns = ham_learns,
        Result = result
    );

    Ok(result.into())
}

trait LookupOrInsert {
    async fn get_or_update(&self, hash: TokenHash, get_token: &LookupStore)
        -> trc::Result<Weights>;
}

impl LookupOrInsert for BayesTokenCache {
    async fn get_or_update(
        &self,
        hash: TokenHash,
        get_token: &LookupStore,
    ) -> trc::Result<Weights> {
        if let Some(weights) = self.get(&hash) {
            Ok(weights.unwrap_or_default())
        } else {
            let num = get_token
                .counter_get(
                    KeySerializer::new(U64_LEN)
                        .write(hash.h1)
                        .write(hash.h2)
                        .finalize(),
                )
                .await
                .caused_by(trc::location!())?;
            Ok(if num != 0 {
                let weights = Weights::from(num);
                self.insert_positive(hash, weights);
                weights
            } else {
                self.insert_negative(hash);
                Weights::default()
            })
        }
    }
}
