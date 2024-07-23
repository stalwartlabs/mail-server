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

pub async fn exec_train(ctx: PluginContext<'_>) -> Variable {
    train(ctx, true).await
}

pub async fn exec_untrain(ctx: PluginContext<'_>) -> Variable {
    train(ctx, false).await
}

async fn train(ctx: PluginContext<'_>, is_train: bool) -> Variable {
    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    };

    let store = if let Some(store) = store {
        store
    } else {
        tracing::warn!(
           
            context = "sieve:bayes_train",
            event = "failed",
            reason = "Unknown store id",
            lookup_store = ctx.arguments[0].to_string().as_ref(),
        );
        return false.into();
    };
    let text = ctx.arguments[1].to_string();
    let is_spam = ctx.arguments[2].to_bool();
    if text.is_empty() {
        tracing::debug!(
           
            context = "sieve:bayes_train",
            event = "failed",
            reason = "Empty message",
        );
        return false.into();
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
        tracing::debug!(
           
            context = "sieve:bayes_train",
            event = "failed",
            reason = "No weights found",
        );
        return false.into();
    }

    tracing::debug!(
       
        context = "sieve:bayes_train",
        event = "train",
        is_spam = is_spam,
        num_tokens = model.weights.len(),
    );

    // Update weight and invalidate cache
    let bayes_cache = &ctx.cache.bayes_cache;
    if is_train {
        for (hash, weights) in model.weights {
            if store
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
                .is_err()
            {
                return false.into();
            }
            bayes_cache.invalidate(&hash);
        }

        // Update training counts
        let weights = if is_spam {
            Weights { spam: 1, ham: 0 }
        } else {
            Weights { spam: 0, ham: 1 }
        };
        if store
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
            .is_err()
        {
            return false.into();
        }
    } else {
        //TODO: Implement untrain
        return false.into();
    }

    bayes_cache.invalidate(&TokenHash::default());

    true.into()
}

pub async fn exec_classify(ctx: PluginContext<'_>) -> Variable {
    
    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    };
    let store = if let Some(store) = store {
        store
    } else {
        tracing::warn!(
           
            context = "sieve:bayes_classify",
            event = "failed",
            reason = "Unknown store id",
            lookup_id = ctx.arguments[0].to_string().as_ref(),
        );
        return Variable::default();
    };
    let text = ctx.arguments[1].to_string();
    if text.is_empty() {
        return Variable::default();
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
    let (spam_learns, ham_learns) =
        if let Some(weights) = bayes_cache.get_or_update(TokenHash::default(), store).await {
            (weights.spam, weights.ham)
        } else {
            tracing::warn!(
               
                context = "sieve:classify",
                event = "failed",
                reason = "Failed to obtain training counts",
            );
            return Variable::default();
        };

    // Make sure we have enough training data
    if spam_learns < classifier.min_learns || ham_learns < classifier.min_learns {
        tracing::debug!(
           
            context = "sieve:bayes_classify",
            event = "skip-classify",
            reason = "Not enough training data",
            min_learns = classifier.min_learns,
            spam_learns = %spam_learns,
            ham_learns = %ham_learns);
        return Variable::default();
    }

    // Classify the text
    let mut tokens = Vec::new();
    for token in OsbTokenizer::<_, TokenHash>::new(
        BayesTokenizer::new(text.as_ref(), &ctx.core.smtp.resolvers.psl),
        5,
    ) {
        if let Some(weights) = bayes_cache.get_or_update(token.inner, store).await {
            tokens.push(OsbToken {
                inner: weights,
                idx: token.idx,
            });
        }
    }
    classifier
        .classify(tokens.into_iter(), ham_learns, spam_learns)
        .map(Variable::from)
        .unwrap_or_default()
}

pub async fn exec_is_balanced(ctx: PluginContext<'_>) -> Variable {
    let min_balance = match &ctx.arguments[2] {
        Variable::Float(n) => *n,
        Variable::Integer(n) => *n as f64,
        _ => 0.0,
    };

    if min_balance == 0.0 {
        return true.into();
    }

    
    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    };
    let store = if let Some(store) = store {
        store
    } else {
        tracing::warn!(
           
            context = "sieve:bayes_is_balanced",
            event = "failed",
            reason = "Unknown store id",
            lookup_id = ctx.arguments[0].to_string().as_ref(),
        );
        return Variable::default();
    };
    let learn_spam = ctx.arguments[1].to_bool();

    // Obtain training counts
    let bayes_cache = &ctx.cache.bayes_cache;
    let (spam_learns, ham_learns) =
        if let Some(weights) = bayes_cache.get_or_update(TokenHash::default(), store).await {
            (weights.spam as f64, weights.ham as f64)
        } else {
            tracing::warn!(
               
                context = "sieve:bayes_is_balanced",
                event = "failed",
                reason = "Failed to obtain training counts",
            );
            return Variable::default();
        };

    let result = if spam_learns > 0.0 || ham_learns > 0.0 {
        if learn_spam {
            (spam_learns / (ham_learns + 1.0)) <= 1.0 / min_balance
        } else {
            (ham_learns / (spam_learns + 1.0)) <= 1.0 / min_balance
        }
    } else {
        true
    };

    tracing::debug!(
       
        context = "sieve:bayes_is_balanced",
        event = "result",
        is_balanced = %result,
        learn_spam = %learn_spam,
        min_balance = %min_balance,
        spam_learns = %spam_learns,
        ham_learns = %ham_learns);

    result.into()
}

trait LookupOrInsert {
    async fn get_or_update(&self, hash: TokenHash, get_token: &LookupStore) -> Option<Weights>;
}

impl LookupOrInsert for BayesTokenCache {
    async fn get_or_update(&self, hash: TokenHash, get_token: &LookupStore) -> Option<Weights> {
        if let Some(weights) = self.get(&hash) {
            weights.unwrap_or_default().into()
        } else if let Ok(num) = get_token
            .counter_get(
                KeySerializer::new(U64_LEN)
                    .write(hash.h1)
                    .write(hash.h2)
                    .finalize(),
            )
            .await
        {
            if num != 0 {
                let weights = Weights::from(num);
                self.insert_positive(hash, weights);
                weights
            } else {
                self.insert_negative(hash);
                Weights::default()
            }
            .into()
        } else {
            // Something went wrong
            None
        }
    }
}
