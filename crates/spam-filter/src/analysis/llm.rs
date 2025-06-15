/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::{future::Future, time::Instant};

use common::Server;
use trc::AiEvent;

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeLlm: Sync + Send {
    fn spam_filter_analyze_llm(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeLlm for Server {
    async fn spam_filter_analyze_llm(&self, ctx: &mut SpamFilterContext<'_>) {
        if let Some(config) = self
            .core
            .enterprise
            .as_ref()
            .and_then(|c| c.spam_filter_llm.as_ref())
        {
            let time = Instant::now();
            let body = if let Some(body) = ctx.text_body() {
                body
            } else {
                return;
            };
            let prompt = format!(
                "{}\n\nSubject: {}\n\n{}",
                config.prompt, ctx.output.subject, body
            );

            match config
                .model
                .send_request(prompt, config.temperature.into())
                .await
            {
                Ok(response) => {
                    trc::event!(
                        Ai(AiEvent::LlmResponse),
                        Id = config.model.id.clone(),
                        Details = response.clone(),
                        Elapsed = time.elapsed(),
                        SpanId = ctx.input.span_id,
                    );

                    let mut category = None;
                    let mut confidence = None;
                    let mut explanation = None;

                    for (idx, value) in response.split(config.separator).enumerate() {
                        let value = value.trim();
                        if !value.is_empty() {
                            if idx == config.index_category {
                                let value = value.to_uppercase();
                                if config.categories.contains(value.as_str()) {
                                    category = Some(value);
                                }
                            } else if config.index_confidence.is_some_and(|i| i == idx) {
                                let value = value.to_uppercase();
                                if config.confidence.contains(value.as_str()) {
                                    confidence = Some(value);
                                }
                            } else if config.index_explanation.is_some_and(|i| i == idx) {
                                let explanation = explanation.get_or_insert_with(|| {
                                    String::with_capacity(std::cmp::min(value.len(), 255))
                                });

                                for value in value.chars() {
                                    if !value.is_whitespace() {
                                        explanation.push(value);
                                    } else {
                                        explanation.push(' ');
                                    }
                                    if explanation.len() == 255 {
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    let category = match (category, confidence) {
                        (Some(category), Some(confidence)) => {
                            ctx.result.add_tag(format!("LLM_{category}_{confidence}"));
                            category
                        }
                        (Some(category), None) => {
                            ctx.result.add_tag(format!("LLM_{category}"));
                            category
                        }
                        _ => return,
                    };

                    if let (Some(header), Some(explanation)) =
                        (&self.core.spam.headers.llm, explanation)
                    {
                        ctx.result.header =
                            format!("{header}: {category} ({explanation})\r\n",).into();
                    }
                }
                Err(err) => {
                    trc::error!(err.span_id(ctx.input.span_id));
                }
            }
        }
    }
}
