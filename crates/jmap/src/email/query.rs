/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    error::method::MethodError,
    method::query::{Comparator, Filter, QueryRequest, QueryResponse, SortProperty},
    object::email::QueryArguments,
    types::{acl::Acl, collection::Collection, keyword::Keyword, property::Property},
};
use mail_parser::HeaderName;
use nlp::language::Language;
use store::{
    fts::{Field, FilterGroup, FtsFilter, IntoFilterGroup},
    query::{self},
    roaring::RoaringBitmap,
    write::ValueClass,
    ValueKey,
};

use crate::{auth::AccessToken, JMAP};

impl JMAP {
    pub async fn email_query(
        &self,
        mut request: QueryRequest<QueryArguments>,
        access_token: &AccessToken,
    ) -> Result<QueryResponse, MethodError> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());

        for cond_group in std::mem::take(&mut request.filter).into_filter_group() {
            match cond_group {
                FilterGroup::Fts(conds) => {
                    let mut fts_filters = Vec::with_capacity(filters.len());
                    for cond in conds {
                        match cond {
                            Filter::Text(text) => {
                                fts_filters.push(FtsFilter::Or);
                                fts_filters.push(FtsFilter::has_text(
                                    Field::Header(HeaderName::From),
                                    &text,
                                    Language::None,
                                ));
                                fts_filters.push(FtsFilter::has_text(
                                    Field::Header(HeaderName::To),
                                    &text,
                                    Language::None,
                                ));
                                fts_filters.push(FtsFilter::has_text(
                                    Field::Header(HeaderName::Cc),
                                    &text,
                                    Language::None,
                                ));
                                fts_filters.push(FtsFilter::has_text(
                                    Field::Header(HeaderName::Bcc),
                                    &text,
                                    Language::None,
                                ));
                                fts_filters.push(FtsFilter::has_text_detect(
                                    Field::Header(HeaderName::Subject),
                                    &text,
                                    self.core.jmap.default_language,
                                ));
                                fts_filters.push(FtsFilter::has_text_detect(
                                    Field::Body,
                                    &text,
                                    self.core.jmap.default_language,
                                ));
                                fts_filters.push(FtsFilter::has_text_detect(
                                    Field::Attachment,
                                    text,
                                    self.core.jmap.default_language,
                                ));
                                fts_filters.push(FtsFilter::End);
                            }
                            Filter::From(text) => fts_filters.push(FtsFilter::has_text(
                                Field::Header(HeaderName::From),
                                text,
                                Language::None,
                            )),
                            Filter::To(text) => fts_filters.push(FtsFilter::has_text(
                                Field::Header(HeaderName::To),
                                text,
                                Language::None,
                            )),
                            Filter::Cc(text) => fts_filters.push(FtsFilter::has_text(
                                Field::Header(HeaderName::Cc),
                                text,
                                Language::None,
                            )),
                            Filter::Bcc(text) => fts_filters.push(FtsFilter::has_text(
                                Field::Header(HeaderName::Bcc),
                                text,
                                Language::None,
                            )),
                            Filter::Subject(text) => fts_filters.push(FtsFilter::has_text_detect(
                                Field::Header(HeaderName::Subject),
                                text,
                                self.core.jmap.default_language,
                            )),
                            Filter::Body(text) => fts_filters.push(FtsFilter::has_text_detect(
                                Field::Body,
                                text,
                                self.core.jmap.default_language,
                            )),
                            Filter::Header(header) => {
                                let mut header = header.into_iter();
                                let header_name = header.next().ok_or_else(|| {
                                    MethodError::InvalidArguments(
                                        "Header name is missing.".to_string(),
                                    )
                                })?;

                                match HeaderName::parse(header_name) {
                                    Some(HeaderName::Other(header_name)) => {
                                        return Err(MethodError::InvalidArguments(format!(
                                            "Querying header '{header_name}' is not supported.",
                                        )));
                                    }
                                    Some(header_name) => {
                                        if let Some(header_value) = header.next() {
                                            if matches!(
                                                header_name,
                                                HeaderName::MessageId
                                                    | HeaderName::InReplyTo
                                                    | HeaderName::References
                                                    | HeaderName::ResentMessageId
                                            ) {
                                                fts_filters.push(FtsFilter::has_keyword(
                                                    Field::Header(header_name),
                                                    header_value,
                                                ));
                                            } else {
                                                fts_filters.push(FtsFilter::has_text(
                                                    Field::Header(header_name),
                                                    header_value,
                                                    Language::None,
                                                ));
                                            }
                                        } else {
                                            fts_filters.push(FtsFilter::has_keyword(
                                                Field::Keyword,
                                                header_name.as_str().to_lowercase(),
                                            ));
                                        }
                                    }
                                    None => (),
                                }
                            }
                            Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                                fts_filters.push(cond.into());
                            }
                            other => return Err(MethodError::UnsupportedFilter(other.to_string())),
                        }
                    }
                    filters.push(query::Filter::is_in_set(
                        self.fts_filter(account_id, Collection::Email, fts_filters)
                            .await?,
                    ));
                }
                FilterGroup::Store(cond) => {
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
                        Filter::Before(date) => {
                            filters.push(query::Filter::lt(Property::ReceivedAt, date))
                        }
                        Filter::After(date) => {
                            filters.push(query::Filter::gt(Property::ReceivedAt, date))
                        }
                        Filter::MinSize(size) => {
                            filters.push(query::Filter::ge(Property::Size, size))
                        }
                        Filter::MaxSize(size) => {
                            filters.push(query::Filter::lt(Property::Size, size))
                        }
                        Filter::AllInThreadHaveKeyword(keyword) => {
                            filters.push(query::Filter::is_in_set(
                                self.thread_keywords(account_id, keyword, true).await?,
                            ))
                        }
                        Filter::SomeInThreadHaveKeyword(keyword) => {
                            filters.push(query::Filter::is_in_set(
                                self.thread_keywords(account_id, keyword, false).await?,
                            ))
                        }
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

                        // Non-standard
                        Filter::Id(ids) => {
                            let mut set = RoaringBitmap::new();
                            for id in ids {
                                set.insert(id.document_id());
                            }
                            filters.push(query::Filter::is_in_set(set));
                        }
                        Filter::SentBefore(date) => {
                            filters.push(query::Filter::lt(Property::SentAt, date))
                        }
                        Filter::SentAfter(date) => {
                            filters.push(query::Filter::gt(Property::SentAt, date))
                        }
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
            }
        }

        let mut result_set = self.filter(account_id, Collection::Email, filters).await?;
        if access_token.is_shared(account_id) {
            result_set.apply_mask(
                self.shared_messages(access_token, account_id, Acl::ReadItems)
                    .await?,
            );
        }
        let (response, paginate) = self.build_query_response(&result_set, &request).await?;

        if let Some(paginate) = paginate {
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
            self.sort(
                result_set,
                comparators,
                paginate
                    .with_prefix_key(ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: 0,
                        class: ValueClass::Property(Property::ThreadId.into()),
                    })
                    .with_prefix_unique(request.arguments.collapse_threads.unwrap_or(false)),
                response,
            )
            .await
        } else {
            Ok(response)
        }
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
        if keyword_doc_ids.is_empty() {
            return Ok(keyword_doc_ids);
        }
        let keyword_thread_ids = self
            .get_cached_thread_ids(account_id, keyword_doc_ids.iter())
            .await?;

        let mut not_matched_ids = RoaringBitmap::new();
        let mut matched_ids = RoaringBitmap::new();

        for (keyword_doc_id, thread_id) in keyword_thread_ids {
            if matched_ids.contains(keyword_doc_id) || not_matched_ids.contains(keyword_doc_id) {
                continue;
            }

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

        Ok(matched_ids)
    }
}
