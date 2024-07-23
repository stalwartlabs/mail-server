/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    method::{
        query::Filter,
        search_snippet::{GetSearchSnippetRequest, GetSearchSnippetResponse, SearchSnippet},
    },
    types::{acl::Acl, collection::Collection, property::Property},
};
use mail_parser::{decoders::html::html_to_text, GetHeader, HeaderName, PartType};
use nlp::language::{search_snippet::generate_snippet, stemmer::Stemmer, Language};
use store::{backend::MAX_TOKEN_LENGTH, write::Bincode};

use crate::{auth::AccessToken, JMAP};

use super::metadata::{MessageMetadata, MetadataPartType};

impl JMAP {
    pub async fn email_search_snippet(
        &self,
        request: GetSearchSnippetRequest,
        access_token: &AccessToken,
    ) -> trc::Result<GetSearchSnippetResponse> {
        let mut filter_stack = vec![];
        let mut include_term = true;
        let mut terms = vec![];
        let mut is_exact = false;
        let mut language = self.core.jmap.default_language;

        for cond in request.filter {
            match cond {
                Filter::Text(text) | Filter::Subject(text) | Filter::Body(text) => {
                    if include_term {
                        let (text, language_) =
                            Language::detect(text, self.core.jmap.default_language);
                        language = language_;
                        if (text.starts_with('"') && text.ends_with('"'))
                            || (text.starts_with('\'') && text.ends_with('\''))
                        {
                            for token in language.tokenize_text(&text, MAX_TOKEN_LENGTH) {
                                terms.push(token.word.into_owned());
                            }
                            is_exact = true;
                        } else {
                            for token in Stemmer::new(&text, language, MAX_TOKEN_LENGTH) {
                                terms.push(token.word.into_owned());
                                if let Some(stemmed_word) = token.stemmed_word {
                                    terms.push(stemmed_word.into_owned());
                                }
                            }
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
            .owned_or_shared_messages(access_token, account_id, Acl::ReadItems)
            .await?;
        let email_ids = request.email_ids.unwrap();
        let mut response = GetSearchSnippetResponse {
            account_id: request.account_id,
            list: Vec::with_capacity(email_ids.len()),
            not_found: vec![],
        };

        if email_ids.len() > self.core.jmap.snippet_max_results {
            return Err(trc::JmapEvent::RequestTooLarge.into_err());
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
            let metadata = match self
                .get_property::<Bincode<MessageMetadata>>(
                    account_id,
                    Collection::Email,
                    document_id,
                    &Property::BodyStructure,
                )
                .await?
            {
                Some(metadata) => metadata.inner,
                None => {
                    response.not_found.push(email_id);
                    continue;
                }
            };

            // Add subject snippet
            if let Some(subject) = metadata
                .contents
                .root_part()
                .headers
                .header_value(&HeaderName::Subject)
                .and_then(|v| v.as_text())
                .and_then(|v| generate_snippet(v, &terms, language, is_exact))
            {
                snippet.subject = subject.into();
            }

            // Check if the snippet can be generated from the preview
            /*if let Some(body) = generate_snippet(&metadata.preview, &terms) {
                snippet.preview = body.into();
            } else {*/
            // Download message
            let raw_message = if let Some(raw_message) =
                self.get_blob(&metadata.blob_hash, 0..usize::MAX).await?
            {
                raw_message
            } else {
                tracing::warn!(event = "not-found",
                    account_id = account_id,
                    collection = ?Collection::Email,
                    document_id = email_id.document_id(),
                    blob_id = ?metadata.blob_hash,
                    "Blob not found");
                response.not_found.push(email_id);
                continue;
            };

            // Find a matching part
            'outer: for part in &metadata.contents.parts {
                match &part.body {
                    MetadataPartType::Text | MetadataPartType::Html => {
                        let text = match part.decode_contents(&raw_message) {
                            PartType::Text(text) => text,
                            PartType::Html(html) => html_to_text(&html).into(),
                            _ => unreachable!(),
                        };

                        if let Some(body) = generate_snippet(&text, &terms, language, is_exact) {
                            snippet.preview = body.into();
                            break;
                        }
                    }
                    MetadataPartType::Message(message) => {
                        for part in &message.parts {
                            if let MetadataPartType::Text | MetadataPartType::Html = part.body {
                                let text = match part.decode_contents(&raw_message) {
                                    PartType::Text(text) => text,
                                    PartType::Html(html) => html_to_text(&html).into(),
                                    _ => unreachable!(),
                                };

                                if let Some(body) =
                                    generate_snippet(&text, &terms, language, is_exact)
                                {
                                    snippet.preview = body.into();
                                    break 'outer;
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
            //}

            response.list.push(snippet);
        }

        Ok(response)
    }
}
