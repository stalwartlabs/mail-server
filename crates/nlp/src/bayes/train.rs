/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::tokenizers::osb::OsbToken;

use super::{BayesModel, TokenHash};

impl BayesModel {
    pub fn train<T>(&mut self, tokens: T, is_spam: bool)
    where
        T: IntoIterator<Item = OsbToken<TokenHash>>,
    {
        if is_spam {
            self.spam_learns += 1;
        } else {
            self.ham_learns += 1;
        }

        for token in tokens {
            let hs = self.weights.entry(token.inner).or_default();
            if is_spam {
                hs.spam += 1;
            } else {
                hs.ham += 1;
            }
        }
    }

    pub fn untrain<T>(&mut self, tokens: T, is_spam: bool)
    where
        T: IntoIterator<Item = OsbToken<TokenHash>>,
    {
        if is_spam {
            self.spam_learns -= 1;
        } else {
            self.ham_learns -= 1;
        }

        for token in tokens {
            let hs = self.weights.entry(token.inner).or_default();
            if is_spam {
                hs.spam -= 1;
            } else {
                hs.ham -= 1;
            }
        }
    }
}
