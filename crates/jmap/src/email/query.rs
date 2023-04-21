use jmap_proto::{
    error::method::MethodError,
    method::query::{Comparator, Filter, QueryRequest, QueryResponse, SortProperty},
    object::email::QueryArguments,
    types::{collection::Collection, keyword::Keyword, property::Property},
};
use mail_parser::{HeaderName, RfcHeader};
use store::{
    fts::{builder::MAX_TOKEN_LENGTH, Language},
    query::{self, sort::Pagination},
    roaring::RoaringBitmap,
    ValueKey,
};

use crate::JMAP;

impl JMAP {
    pub async fn email_query(
        &self,
        request: QueryRequest<QueryArguments>,
    ) -> Result<QueryResponse, MethodError> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());

        for cond in request.filter {
            match cond {
                Filter::InMailbox(mailbox) => filters.push(query::Filter::is_in_bitmap(
                    Property::MailboxIds,
                    mailbox.document_id(),
                )),
                Filter::InMailboxOtherThan(mailboxes) => {
                    filters.push(query::Filter::Not);
                    filters.push(query::Filter::Or);
                    for mailbox in mailboxes {
                        filters.push(query::Filter::is_in_bitmap(
                            Property::MailboxIds,
                            mailbox.document_id(),
                        ));
                    }
                    filters.push(query::Filter::End);
                    filters.push(query::Filter::End);
                }
                Filter::Before(date) => filters.push(query::Filter::lt(Property::ReceivedAt, date)),
                Filter::After(date) => filters.push(query::Filter::gt(Property::ReceivedAt, date)),
                Filter::MinSize(size) => filters.push(query::Filter::ge(Property::Size, size)),
                Filter::MaxSize(size) => filters.push(query::Filter::lt(Property::Size, size)),
                Filter::AllInThreadHaveKeyword(keyword) => filters.push(query::Filter::is_in_set(
                    self.thread_keywords(account_id, keyword, true).await?,
                )),
                Filter::SomeInThreadHaveKeyword(keyword) => filters.push(query::Filter::is_in_set(
                    self.thread_keywords(account_id, keyword, false).await?,
                )),
                Filter::NoneInThreadHaveKeyword(keyword) => {
                    filters.push(query::Filter::Not);
                    filters.push(query::Filter::is_in_set(
                        self.thread_keywords(account_id, keyword, false).await?,
                    ));
                    filters.push(query::Filter::End);
                }
                Filter::HasKeyword(keyword) => {
                    filters.push(query::Filter::is_in_bitmap(Property::Keywords, keyword))
                }
                Filter::NotKeyword(keyword) => {
                    filters.push(query::Filter::Not);
                    filters.push(query::Filter::is_in_bitmap(Property::Keywords, keyword));
                    filters.push(query::Filter::End);
                }
                Filter::HasAttachment(has_attach) => {
                    if !has_attach {
                        filters.push(query::Filter::Not);
                    }
                    filters.push(query::Filter::is_in_bitmap(Property::HasAttachment, ()));
                    if !has_attach {
                        filters.push(query::Filter::End);
                    }
                }
                Filter::Text(text) => {
                    filters.push(query::Filter::Or);
                    filters.push(query::Filter::has_text(
                        Property::From,
                        &text,
                        Language::None,
                    ));
                    filters.push(query::Filter::has_text(Property::To, &text, Language::None));
                    filters.push(query::Filter::has_text(Property::Cc, &text, Language::None));
                    filters.push(query::Filter::has_text(
                        Property::Bcc,
                        &text,
                        Language::None,
                    ));
                    filters.push(query::Filter::has_text_detect(
                        Property::Subject,
                        &text,
                        self.config.default_language,
                    ));
                    filters.push(query::Filter::has_text_detect(
                        Property::TextBody,
                        &text,
                        self.config.default_language,
                    ));
                    filters.push(query::Filter::has_text_detect(
                        Property::Attachments,
                        text,
                        self.config.default_language,
                    ));
                    filters.push(query::Filter::End);
                }
                Filter::From(text) => filters.push(query::Filter::has_text(
                    Property::From,
                    text,
                    Language::None,
                )),
                Filter::To(text) => {
                    filters.push(query::Filter::has_text(Property::To, text, Language::None))
                }
                Filter::Cc(text) => {
                    filters.push(query::Filter::has_text(Property::Cc, text, Language::None))
                }
                Filter::Bcc(text) => {
                    filters.push(query::Filter::has_text(Property::Bcc, text, Language::None))
                }
                Filter::Subject(text) => filters.push(query::Filter::has_text_detect(
                    Property::Subject,
                    text,
                    self.config.default_language,
                )),
                Filter::Body(text) => filters.push(query::Filter::has_text_detect(
                    Property::TextBody,
                    text,
                    self.config.default_language,
                )),
                Filter::Header(header) => {
                    let mut header = header.into_iter();
                    let header_name = header.next().ok_or_else(|| {
                        MethodError::InvalidArguments("Header name is missing.".to_string())
                    })?;
                    if let Some(HeaderName::Rfc(header_name)) = HeaderName::parse(&header_name) {
                        let is_id = matches!(
                            header_name,
                            RfcHeader::MessageId
                                | RfcHeader::InReplyTo
                                | RfcHeader::References
                                | RfcHeader::ResentMessageId
                        );
                        let tokens = if let Some(header_value) = header.next() {
                            let header_num = u8::from(header_name).to_string();
                            header_value
                                .split_ascii_whitespace()
                                .filter_map(|token| {
                                    if token.len() < MAX_TOKEN_LENGTH {
                                        if is_id {
                                            format!("{header_num}{token}")
                                        } else {
                                            format!("{header_num}{}", token.to_lowercase())
                                        }
                                        .into()
                                    } else {
                                        None
                                    }
                                })
                                .collect::<Vec<_>>()
                        } else {
                            vec![]
                        };
                        match tokens.len() {
                            0 => {
                                filters.push(query::Filter::has_raw_text(
                                    Property::Headers,
                                    u8::from(header_name).to_string(),
                                ));
                            }
                            1 => {
                                filters.push(query::Filter::has_raw_text(
                                    Property::Headers,
                                    tokens.into_iter().next().unwrap(),
                                ));
                            }
                            _ => {
                                filters.push(query::Filter::And);
                                for token in tokens {
                                    filters.push(query::Filter::has_raw_text(
                                        Property::Headers,
                                        token,
                                    ));
                                }
                                filters.push(query::Filter::End);
                            }
                        }
                    } else {
                        return Err(MethodError::InvalidArguments(format!(
                            "Querying non-RFC header '{header_name}' is not allowed.",
                        )));
                    };
                }

                // Non-standard
                Filter::Id(ids) => {
                    let mut set = RoaringBitmap::new();
                    for id in ids {
                        set.insert(id.document_id());
                    }
                    filters.push(query::Filter::is_in_set(set));
                }
                Filter::SentBefore(date) => filters.push(query::Filter::lt(Property::SentAt, date)),
                Filter::SentAfter(date) => filters.push(query::Filter::gt(Property::SentAt, date)),
                Filter::InThread(id) => filters.push(query::Filter::is_in_bitmap(
                    Property::ThreadId,
                    id.document_id(),
                )),
                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    filters.push(cond.into());
                }

                other => return Err(MethodError::UnsupportedFilter(other.to_string())),
            }
        }

        let result_set = match self
            .store
            .filter(account_id, Collection::Email, filters)
            .await
        {
            Ok(result_set) => result_set,
            Err(err) => {
                tracing::error!(event = "error",
                    context = "store",
                    account_id = account_id,
                    collection = "email",
                    error = ?err,
                    "Filter failed");
                return Err(MethodError::ServerPartialFail);
            }
        };
        let total = result_set.results.len() as usize;
        let (limit_total, limit) = if let Some(limit) = request.limit {
            if limit > 0 {
                let limit = std::cmp::min(limit, self.config.query_max_results);
                (std::cmp::min(limit, total), limit)
            } else {
                (0, 0)
            }
        } else {
            (
                std::cmp::min(self.config.query_max_results, total),
                self.config.query_max_results,
            )
        };
        let mut response = QueryResponse {
            account_id: request.account_id,
            query_state: self.get_state(account_id, Collection::Email).await?,
            can_calculate_changes: true,
            position: 0,
            ids: vec![],
            total: if request.calculate_total.unwrap_or(false) {
                Some(total)
            } else {
                None
            },
            limit: if total > limit { Some(limit) } else { None },
        };

        if limit_total > 0 {
            // Parse sort criteria
            let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));
            for comparator in request
                .sort
                .and_then(|s| if !s.is_empty() { s.into() } else { None })
                .unwrap_or_else(|| vec![Comparator::descending(SortProperty::ReceivedAt)])
            {
                comparators.push(match comparator.property {
                    SortProperty::ReceivedAt => {
                        query::Comparator::field(Property::ReceivedAt, comparator.is_ascending)
                    }
                    SortProperty::Size => {
                        query::Comparator::field(Property::Size, comparator.is_ascending)
                    }
                    SortProperty::From => {
                        query::Comparator::field(Property::From, comparator.is_ascending)
                    }
                    SortProperty::To => {
                        query::Comparator::field(Property::To, comparator.is_ascending)
                    }
                    SortProperty::Subject => {
                        query::Comparator::field(Property::Subject, comparator.is_ascending)
                    }
                    SortProperty::SentAt => {
                        query::Comparator::field(Property::SentAt, comparator.is_ascending)
                    }
                    SortProperty::HasKeyword => query::Comparator::set(
                        self.get_tag(
                            account_id,
                            Collection::Email,
                            Property::Keywords,
                            comparator.keyword.unwrap_or(Keyword::Seen),
                        )
                        .await?
                        .unwrap_or_default(),
                        comparator.is_ascending,
                    ),
                    SortProperty::AllInThreadHaveKeyword => query::Comparator::set(
                        self.thread_keywords(
                            account_id,
                            comparator.keyword.unwrap_or(Keyword::Seen),
                            true,
                        )
                        .await?,
                        comparator.is_ascending,
                    ),
                    SortProperty::SomeInThreadHaveKeyword => query::Comparator::set(
                        self.thread_keywords(
                            account_id,
                            comparator.keyword.unwrap_or(Keyword::Seen),
                            false,
                        )
                        .await?,
                        comparator.is_ascending,
                    ),
                    // Non-standard
                    SortProperty::Cc => {
                        query::Comparator::field(Property::Cc, comparator.is_ascending)
                    }

                    other => return Err(MethodError::UnsupportedSort(other.to_string())),
                });
            }

            // Sort results
            let result = match self
                .store
                .sort(
                    result_set,
                    comparators,
                    Pagination::new(
                        limit_total,
                        request.position.unwrap_or(0),
                        request.anchor.map(|a| a.document_id()),
                        request.anchor_offset.unwrap_or(0),
                        ValueKey::new(account_id, Collection::Email, 0, Property::ThreadId).into(),
                        request.arguments.collapse_threads.unwrap_or(false),
                    ),
                )
                .await
            {
                Ok(result) => result,
                Err(err) => {
                    tracing::error!(event = "error",
                    context = "store",
                    account_id = account_id,
                    collection = "email",
                    error = ?err,
                    "Sort failed");
                    return Err(MethodError::ServerPartialFail);
                }
            };

            // Prepare response
            if result.found_anchor {
                response.position = result.position;
                response.ids = result
                    .ids
                    .into_iter()
                    .map(|id| id.into())
                    .collect::<Vec<_>>();
            } else {
                return Err(MethodError::AnchorNotFound);
            }
        }

        Ok(response)
    }

    async fn thread_keywords(
        &self,
        account_id: u32,
        keyword: Keyword,
        match_all: bool,
    ) -> Result<RoaringBitmap, MethodError> {
        let keyword_doc_ids = self
            .get_tag(account_id, Collection::Email, Property::Keywords, keyword)
            .await?
            .unwrap_or_default();

        let mut not_matched_ids = RoaringBitmap::new();
        let mut matched_ids = RoaringBitmap::new();

        for keyword_doc_id in &keyword_doc_ids {
            if matched_ids.contains(keyword_doc_id) || not_matched_ids.contains(keyword_doc_id) {
                continue;
            }
            if let Some(thread_id) = self
                .get_property::<u32>(
                    account_id,
                    Collection::Email,
                    keyword_doc_id,
                    &Property::ThreadId,
                )
                .await?
            {
                if let Some(thread_doc_ids) = self
                    .get_tag(account_id, Collection::Email, Property::ThreadId, thread_id)
                    .await?
                {
                    let mut thread_tag_intersection = thread_doc_ids.clone();
                    thread_tag_intersection &= &keyword_doc_ids;

                    if (match_all && thread_tag_intersection == thread_doc_ids)
                        || (!match_all && !thread_tag_intersection.is_empty())
                    {
                        matched_ids |= &thread_doc_ids;
                    } else if !thread_tag_intersection.is_empty() {
                        not_matched_ids |= &thread_tag_intersection;
                    }
                }
            }
        }

        Ok(matched_ids)
    }
}
