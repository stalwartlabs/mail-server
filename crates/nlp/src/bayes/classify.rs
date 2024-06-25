/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::tokenizers::osb::OsbToken;

use super::{BayesClassifier, Weights};

// Position 0 represents Unigram weights
const FEATURE_WEIGHT: [f64; 8] = [1.0, 3125.0, 256.0, 27.0, 1.0, 0.0, 0.0, 0.0];

// Credits: ported from RSpamd
impl BayesClassifier {
    pub fn classify<T>(&self, tokens: T, ham_learns: u32, spam_learns: u32) -> Option<f64>
    where
        T: Iterator<Item = OsbToken<Weights>>,
    {
        if self.min_learns > 0 && (spam_learns < self.min_learns || ham_learns < self.min_learns) {
            return None;
        }

        let mut processed_tokens = 0;
        let mut total_spam_prob = 0.0;
        let mut total_ham_prob = 0.0;

        for token in tokens {
            let weights = token.inner;
            let total_count = weights.spam + weights.ham;

            if total_count >= self.min_token_hits {
                let total_count = total_count as f64;
                let spam_freq = weights.spam as f64 / f64::max(1.0, spam_learns as f64);
                let ham_freq = weights.ham as f64 / f64::max(1.0, ham_learns as f64);
                let spam_prob = spam_freq / (spam_freq + ham_freq);
                let ham_prob = ham_freq / (spam_freq + ham_freq);

                let fw = FEATURE_WEIGHT[token.idx];
                let w = (fw * total_count) / (1.0 + fw * total_count);
                let bayes_spam_prob = prob_combine(spam_prob, total_count, w, 0.5);

                if !((bayes_spam_prob > 0.5 && bayes_spam_prob < 0.5 + self.min_prob_strength)
                    || (bayes_spam_prob < 0.5 && bayes_spam_prob > 0.5 - self.min_prob_strength))
                {
                    let bayes_ham_prob = prob_combine(ham_prob, total_count, w, 0.5);
                    total_spam_prob += bayes_spam_prob.ln();
                    total_ham_prob += bayes_ham_prob.ln();
                    processed_tokens += 1;
                }
            }
        }

        if processed_tokens == 0 || self.min_tokens > 0 && processed_tokens < self.min_tokens {
            return None;
        }

        let (h, s) = if total_spam_prob > -300.0 && total_ham_prob > -300.0 {
            /* Fisher value is low enough to apply inv_chi_square */
            (
                1.0 - inv_chi_square(total_spam_prob, processed_tokens),
                1.0 - inv_chi_square(total_ham_prob, processed_tokens),
            )
        } else {
            /* Use naive method */
            if total_spam_prob < total_ham_prob {
                let h = (1.0 - (total_spam_prob - total_ham_prob).exp())
                    / (1.0 + (total_spam_prob - total_ham_prob).exp());
                (h, 1.0 - h)
            } else {
                let s = (1.0 - (total_ham_prob - total_spam_prob).exp())
                    / (1.0 + (total_ham_prob - total_spam_prob).exp());
                (1.0 - s, s)
            }
        };

        let final_prob = if h.is_finite() && s.is_finite() {
            (s + 1.0 - h) / 2.0
        } else {
            /*
             * We have some overflow, hence we need to check which class
             * is NaN
             */

            if h.is_finite() {
                1.0
            } else if s.is_finite() {
                0.0
            } else {
                0.5
            }
        };

        if processed_tokens > 0 && (final_prob - 0.5).abs() > 0.05 {
            Some(final_prob)
        } else {
            None
        }
    }
}

/**
 * Returns probability of chisquare > value with specified number of freedom
 * degrees
 */
#[inline(always)]
fn inv_chi_square(value: f64, freedom_deg: u32) -> f64 {
    let mut prob = value.exp();

    if prob.is_finite() {
        /*
         * m is our confidence in class
         * prob is e ^ x (small value since x is normally less than zero
         * So we integrate over degrees of freedom and produce the total result
         * from 1.0 (no confidence) to 0.0 (full confidence)
         */

        let mut sum = prob;
        let m = -value;

        for i in 1..freedom_deg {
            prob *= m / i as f64;
            sum += prob;
        }

        f64::min(1.0, sum)
    } else {
        /*
         * e^x where x is large *NEGATIVE* number is OK, so we have a very strong
         * confidence that inv-chi-square is close to zero
         */

        if value < 0.0 {
            0.0
        } else {
            1.0
        }
    }
}

/*#[inline(always)]
fn normalize_probability(x: f64, bias: f64) -> f64 {
    ((x - bias) * 2.0).powi(8)
}*/

#[inline(always)]
fn prob_combine(prob: f64, cnt: f64, weight: f64, assumed: f64) -> f64 {
    ((weight) * (assumed) + (cnt) * (prob)) / ((weight) + (cnt))
}
