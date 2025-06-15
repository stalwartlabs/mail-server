/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod bayes;
pub mod language;
pub mod tokenizers;

#[cfg(test)]
mod test {
    use std::fs;

    use crate::{
        bayes::{
            BayesClassifier, BayesModel,
            tokenize::{BayesTokenizer, tests::ToBayesToken},
        },
        tokenizers::{
            osb::{OsbToken, OsbTokenizer},
            types::TypesTokenizer,
        },
    };

    #[test]
    #[ignore]
    fn train() {
        let db =
            fs::read_to_string("/Users/me/code/stalwart/_ignore/old/spam_or_not_spam.csv").unwrap();
        let mut bayes = BayesModel::default();

        for line in db.lines() {
            let (text, is_spam) = line.rsplit_once(',').unwrap();
            let is_spam = is_spam == "1";

            bayes.train(
                OsbTokenizer::new(
                    BayesTokenizer::new(
                        text,
                        TypesTokenizer::new(text).filter_map(|t| t.word.to_bayes_token()),
                    ),
                    5,
                ),
                is_spam,
            );
        }
        println!("Ham: {} Spam: {}", bayes.ham_learns, bayes.spam_learns,);
        fs::write(
            "/Users/me/code/stalwart/_ignore/old/spam_or_not_spam.bin",
            bincode::serialize(&bayes).unwrap(),
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    fn classify() {
        let model: BayesModel = bincode::deserialize(
            &fs::read("/Users/me/code/stalwart/_ignore/old/spam_or_not_spam.bin").unwrap(),
        )
        .unwrap();
        let bayes = BayesClassifier::new();

        for text in [
            concat!(
                "i am attaching to this email a presentation to integrate the ",
                "spreadsheet into our server and obtain the data from the database"
            ),
            "buy this great product special offer sales",
            concat!(
                "i m using simple dns from jhsoft we support only a few web sites ",
                "and i d like to swap secondary services with someone in a similar position"
            ),
            "viagra xenical vioxx zyban propecia we only offer the real viagra xenical ",
        ] {
            println!(
                "{:?} -> {:?}",
                text,
                bayes
                    .classify(
                        OsbTokenizer::new(
                            BayesTokenizer::new(
                                text,
                                TypesTokenizer::new(text).filter_map(|t| t.word.to_bayes_token())
                            ),
                            5
                        )
                        .filter_map(|x| model.weights.get(&x.inner).map(
                            |w| {
                                OsbToken {
                                    idx: x.idx,
                                    inner: *w,
                                }
                            }
                        )),
                        model.ham_learns,
                        model.spam_learns
                    )
                    .unwrap()
            );
        }
    }
}
