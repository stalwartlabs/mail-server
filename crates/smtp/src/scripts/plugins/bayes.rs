/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use directory::{DatabaseColumn, Lookup};
use nlp::{
    bayes::{
        cache::BayesTokenCache, tokenize::BayesTokenizer, BayesClassifier, BayesModel, TokenHash,
        Weights,
    },
    tokenizers::osb::{OsbToken, OsbTokenizer},
};
use sieve::{runtime::Variable, FunctionMap};
use tokio::runtime::Handle;

use crate::config::scripts::SieveContext;

use super::PluginContext;

pub fn register_train(plugin_id: u32, fnc_map: &mut FunctionMap<SieveContext>) {
    fnc_map.set_external_function("bayes_train", plugin_id, 3);
}

pub fn register_untrain(plugin_id: u32, fnc_map: &mut FunctionMap<SieveContext>) {
    fnc_map.set_external_function("bayes_untrain", plugin_id, 3);
}

pub fn register_classify(plugin_id: u32, fnc_map: &mut FunctionMap<SieveContext>) {
    fnc_map.set_external_function("bayes_classify", plugin_id, 3);
}

pub fn register_is_balanced(plugin_id: u32, fnc_map: &mut FunctionMap<SieveContext>) {
    fnc_map.set_external_function("bayes_is_balanced", plugin_id, 3);
}

pub fn exec_train(ctx: PluginContext<'_>) -> Variable {
    train(ctx, true)
}

pub fn exec_untrain(ctx: PluginContext<'_>) -> Variable {
    train(ctx, false)
}

fn train(ctx: PluginContext<'_>, is_train: bool) -> Variable {
    let span = ctx.span;
    let lookup_id = ctx.arguments[0].to_string();
    let lookup_train = if let Some(lookup_train) = ctx.core.sieve.lookup.get(lookup_id.as_ref()) {
        lookup_train
    } else {
        tracing::warn!(
            parent: span,
            context = "sieve:bayes_train",
            event = "failed",
            reason = "Unknown lookup id",
            lookup_id = %lookup_id,
        );
        return false.into();
    };
    let text = ctx.arguments[1].to_string();
    let is_spam = ctx.arguments[2].to_bool();
    if text.is_empty() {
        return false.into();
    }
    let handle = ctx.handle;
    let ctx = ctx.core.sieve.runtime.context();

    // Train the model
    let mut model = BayesModel::default();
    model.train(
        OsbTokenizer::new(BayesTokenizer::new(text.as_ref(), &ctx.psl), 5),
        is_spam,
    );
    if model.weights.is_empty() {
        return false.into();
    }

    tracing::debug!(
        parent: span,
        context = "sieve:bayes_train",
        event = "classify",
        is_spam = is_spam,
        num_tokens = model.weights.len(),
    );

    // Update weight and invalidate cache
    for (hash, weights) in model.weights {
        let (s_weight, h_weight) = if is_train {
            (weights.spam as i64, weights.ham as i64)
        } else {
            (-(weights.spam as i64), -(weights.ham as i64))
        };
        if handle
            .block_on(lookup_train.lookup(&[
                hash.h1.into(),
                hash.h2.into(),
                s_weight.into(),
                h_weight.into(),
            ]))
            .is_none()
        {
            return false.into();
        }
        ctx.bayes_cache.invalidate(&hash);
    }

    // Update training counts
    let train_val = if is_train { 1i64 } else { -1i64 };
    let (spam_count, ham_count) = if is_spam {
        (train_val, 0i64)
    } else {
        (0i64, train_val)
    };
    if handle
        .block_on(lookup_train.query(&[
            0i64.into(),
            0i64.into(),
            spam_count.into(),
            ham_count.into(),
        ]))
        .is_none()
    {
        return false.into();
    }
    ctx.bayes_cache.invalidate(&TokenHash::default());

    true.into()
}

pub fn exec_classify(ctx: PluginContext<'_>) -> Variable {
    let span = ctx.span;
    let lookup_id = ctx.arguments[0].to_string();
    let lookup_classify =
        if let Some(lookup_classify) = ctx.core.sieve.lookup.get(lookup_id.as_ref()) {
            lookup_classify
        } else {
            tracing::warn!(
                parent: span,
                context = "sieve:bayes_classify",
                event = "failed",
                reason = "Unknown lookup id",
                lookup_id = %lookup_id,
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
        if let Some(Variable::Integer(value)) = params.get(0) {
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

    let handle = ctx.handle;
    let ctx = ctx.core.sieve.runtime.context();

    // Obtain training counts
    let (spam_learns, ham_learns) = if let Some(weights) =
        ctx.bayes_cache
            .get_or_update(TokenHash::default(), handle, lookup_classify)
    {
        (weights.spam, weights.ham)
    } else {
        tracing::warn!(
            parent: span,
            context = "sieve:classify",
            event = "failed",
            reason = "Failed to obtain training counts",
        );
        return Variable::default();
    };

    // Make sure we have enough training data
    if spam_learns < classifier.min_learns || ham_learns < classifier.min_learns {
        tracing::debug!(
            parent: span,
            context = "sieve:bayes_classify",
            event = "skip-classify",
            reason = "Not enough training data",
            spam_learns = %spam_learns,
            ham_learns = %ham_learns);
        return Variable::default();
    }

    // Classify the text
    classifier
        .classify(
            OsbTokenizer::<_, TokenHash>::new(BayesTokenizer::new(text.as_ref(), &ctx.psl), 5)
                .filter_map(|t| {
                    OsbToken {
                        inner: ctx
                            .bayes_cache
                            .get_or_update(t.inner, handle, lookup_classify)?,
                        idx: t.idx,
                    }
                    .into()
                }),
            ham_learns,
            spam_learns,
        )
        .map(Variable::from)
        .unwrap_or_default()
}

pub fn exec_is_balanced(ctx: PluginContext<'_>) -> Variable {
    let min_balance = match &ctx.arguments[2] {
        Variable::Float(n) => *n,
        Variable::Integer(n) => *n as f64,
        _ => 0.0,
    };

    if min_balance == 0.0 {
        return true.into();
    }

    let span = ctx.span;
    let lookup_id = ctx.arguments[0].to_string();
    let lookup_classify =
        if let Some(lookup_classify) = ctx.core.sieve.lookup.get(lookup_id.as_ref()) {
            lookup_classify
        } else {
            tracing::warn!(
                parent: span,
                context = "sieve:bayes_is_balanced",
                event = "failed",
                reason = "Unknown lookup id",
                lookup_id = %lookup_id,
            );
            return Variable::default();
        };
    let learn_spam = ctx.arguments[2].to_bool();

    // Obtain training counts
    let handle = ctx.handle;
    let ctx = ctx.core.sieve.runtime.context();
    let (spam_learns, ham_learns) = if let Some(weights) =
        ctx.bayes_cache
            .get_or_update(TokenHash::default(), handle, lookup_classify)
    {
        (weights.spam as f64, weights.ham as f64)
    } else {
        tracing::warn!(
            parent: span,
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
        parent: span,
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
    fn get_or_update(
        &self,
        hash: TokenHash,
        handle: &Handle,
        get_token: &Lookup,
    ) -> Option<Weights>;
}

impl LookupOrInsert for BayesTokenCache {
    fn get_or_update(
        &self,
        hash: TokenHash,
        handle: &Handle,
        get_token: &Lookup,
    ) -> Option<Weights> {
        if let Some(weights) = self.get(&hash) {
            weights.unwrap_or_default().into()
        } else if let Some(result) =
            handle.block_on(get_token.query(&[hash.h1.into(), hash.h2.into()]))
        {
            let mut result = result.into_iter();
            match (result.next(), result.next()) {
                (Some(DatabaseColumn::Integer(spam)), Some(DatabaseColumn::Integer(ham))) => {
                    let weights = Weights {
                        spam: spam as u32,
                        ham: ham as u32,
                    };
                    self.insert_positive(hash, weights);
                    weights
                }
                _ => {
                    self.insert_negative(hash);
                    Weights::default()
                }
            }
            .into()
        } else {
            // Something went wrong
            None
        }
    }
}
