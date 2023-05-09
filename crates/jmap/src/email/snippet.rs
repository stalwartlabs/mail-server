use jmap_proto::{
    error::method::MethodError,
    method::{
        query::Filter,
        search_snippet::{GetSearchSnippetRequest, GetSearchSnippetResponse, SearchSnippet},
    },
    types::{acl::Acl, collection::Collection},
};
use mail_parser::{decoders::html::html_to_text, Message, PartType};
use store::{
    fts::{
        builder::MAX_TOKEN_LENGTH,
        search_snippet::generate_snippet,
        stemmer::Stemmer,
        term_index::{self, TermIndex},
        tokenizers::Tokenizer,
        Language,
    },
    BlobKind,
};

use crate::{auth::AclToken, JMAP};

use super::index::MAX_MESSAGE_PARTS;

impl JMAP {
    pub async fn email_search_snippet(
        &self,
        request: GetSearchSnippetRequest,
        acl_token: &AclToken,
    ) -> Result<GetSearchSnippetResponse, MethodError> {
        let mut filter_stack = vec![];
        let mut include_term = true;
        let mut terms = vec![];
        let mut match_phrase = false;

        for cond in request.filter {
            match cond {
                Filter::Text(text) | Filter::Subject(text) | Filter::Body(text) => {
                    if include_term {
                        let (text, language) = Language::detect(text, self.config.default_language);
                        if (text.starts_with('"') && text.ends_with('"'))
                            || (text.starts_with('\'') && text.ends_with('\''))
                        {
                            terms.push(
                                Tokenizer::new(&text, language, MAX_TOKEN_LENGTH)
                                    .map(|token| (token.word.into_owned(), None))
                                    .collect::<Vec<_>>(),
                            );
                            match_phrase = true;
                        } else {
                            terms.push(
                                Stemmer::new(&text, language, MAX_TOKEN_LENGTH)
                                    .map(|token| {
                                        (
                                            token.word.into_owned(),
                                            token.stemmed_word.map(|w| w.into_owned()),
                                        )
                                    })
                                    .collect::<Vec<_>>(),
                            );
                        }
                    }
                }
                Filter::And | Filter::Or => {
                    filter_stack.push(cond);
                }
                Filter::Not => {
                    filter_stack.push(cond);
                    include_term = !include_term;
                }
                Filter::Close => {
                    if matches!(filter_stack.pop(), Some(Filter::Not)) {
                        include_term = !include_term;
                    }
                }
                _ => (),
            }
        }
        let account_id = request.account_id.document_id();
        let document_ids = self
            .owned_or_shared_messages(acl_token, account_id, Acl::ReadItems)
            .await?;
        let email_ids = request.email_ids.unwrap();
        let mut response = GetSearchSnippetResponse {
            account_id: request.account_id,
            list: Vec::with_capacity(email_ids.len()),
            not_found: vec![],
        };

        if email_ids.len() > self.config.get_max_objects {
            return Err(MethodError::RequestTooLarge);
        }

        for email_id in email_ids {
            let document_id = email_id.document_id();
            let mut snippet = SearchSnippet {
                email_id,
                subject: None,
                preview: None,
            };
            if !document_ids.contains(document_id) {
                response.not_found.push(email_id);
                continue;
            } else if terms.is_empty() {
                response.list.push(snippet);
                continue;
            }

            // Obtain the term index and raw message
            let (term_index, raw_message) = if let (Some(term_index), Some(raw_message)) = (
                self.get_term_index::<TermIndex>(account_id, Collection::Email, document_id)
                    .await?,
                self.get_blob(
                    &BlobKind::LinkedMaildir {
                        account_id,
                        document_id,
                    },
                    0..u32::MAX,
                )
                .await?,
            ) {
                (term_index, raw_message)
            } else {
                response.not_found.push(email_id);
                continue;
            };

            // Parse message
            let message = if let Some(message) = Message::parse(&raw_message) {
                message
            } else {
                response.not_found.push(email_id);
                continue;
            };

            // Build the match terms
            let mut match_terms = Vec::new();
            for term in &terms {
                for (word, stemmed_word) in term {
                    match_terms.push(term_index.get_match_term(word, stemmed_word.as_deref()));
                }
            }

            'outer: for term_group in term_index
                .match_terms(&match_terms, None, match_phrase, true, true)
                .map_err(|err| match err {
                    term_index::Error::InvalidArgument => {
                        MethodError::UnsupportedFilter("Too many search terms.".to_string())
                    }
                    err => {
                        tracing::error!(
                            account_id = account_id,
                            document_id = document_id,
                            reason = ?err,
                            "Failed to generate search snippet.");
                        MethodError::UnsupportedFilter(
                            "Failed to generate search snippet.".to_string(),
                        )
                    }
                })?
                .unwrap_or_default()
            {
                if term_group.part_id == 0 {
                    // Generate subject snippent
                    snippet.subject =
                        generate_snippet(&term_group.terms, message.subject().unwrap_or_default());
                } else {
                    let mut part_num = 1;
                    for part in &message.parts {
                        match &part.body {
                            PartType::Text(text) => {
                                if part_num == term_group.part_id {
                                    snippet.preview = generate_snippet(&term_group.terms, text);
                                    break 'outer;
                                } else {
                                    part_num += 1;
                                }
                            }
                            PartType::Html(html) => {
                                if part_num == term_group.part_id {
                                    snippet.preview =
                                        generate_snippet(&term_group.terms, &html_to_text(html));
                                    break 'outer;
                                } else {
                                    part_num += 1;
                                }
                            }
                            PartType::Message(message) => {
                                if let Some(subject) = message.subject() {
                                    if part_num == term_group.part_id {
                                        snippet.preview =
                                            generate_snippet(&term_group.terms, subject);
                                        break 'outer;
                                    } else {
                                        part_num += 1;
                                    }
                                }
                                for sub_part in message.parts.iter().take(MAX_MESSAGE_PARTS) {
                                    match &sub_part.body {
                                        PartType::Text(text) => {
                                            if part_num == term_group.part_id {
                                                snippet.preview =
                                                    generate_snippet(&term_group.terms, text);
                                                break 'outer;
                                            } else {
                                                part_num += 1;
                                            }
                                        }
                                        PartType::Html(html) => {
                                            if part_num == term_group.part_id {
                                                snippet.preview = generate_snippet(
                                                    &term_group.terms,
                                                    &html_to_text(html),
                                                );
                                                break 'outer;
                                            } else {
                                                part_num += 1;
                                            }
                                        }
                                        _ => (),
                                    }
                                }
                            }
                            _ => (),
                        }
                    }
                }
            }

            response.list.push(snippet);
        }

        Ok(response)
    }
}
