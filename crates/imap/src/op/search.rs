/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::listener::SessionStream;
use imap_proto::{
    protocol::{
        search::{self, Arguments, Filter, Response, ResultOption},
        Sequence,
    },
    receiver::Request,
    Command, StatusResponse,
};
use jmap_proto::types::{collection::Collection, id::Id, keyword::Keyword, property::Property};
use mail_parser::HeaderName;
use nlp::language::Language;
use store::{
    fts::{Field, FilterGroup, FtsFilter, IntoFilterGroup},
    query::{self, log::Query, sort::Pagination, ResultSet},
    roaring::RoaringBitmap,
    write::now,
};
use tokio::sync::watch;
use trc::AddContext;

use crate::{
    core::{ImapId, MailboxState, SavedSearch, SelectedMailbox, Session, SessionData},
    spawn_op,
};

use super::{FromModSeq, ToModSeq};

impl<T: SessionStream> Session<T> {
    pub async fn handle_search(
        &mut self,
        request: Request<Command>,
        is_sort: bool,
        is_uid: bool,
    ) -> trc::Result<()> {
        let mut arguments = if !is_sort {
            request.parse_search(self.version)
        } else {
            request.parse_sort()
        }?;

        let (data, mailbox) = self.state.mailbox_state();

        // Create channel for results
        let (results_tx, prev_saved_search) =
            if arguments.result_options.contains(&ResultOption::Save) {
                let prev_saved_search = Some(mailbox.get_saved_search().await);
                let (tx, rx) = watch::channel(Arc::new(Vec::new()));
                *mailbox.saved_search.lock() = SavedSearch::InFlight { rx };
                (tx.into(), prev_saved_search)
            } else {
                (None, None)
            };

        spawn_op!(data, {
            let tag = std::mem::take(&mut arguments.tag);
            let bytes = match data
                .search(
                    arguments,
                    mailbox.clone(),
                    results_tx,
                    prev_saved_search.clone(),
                    is_uid,
                )
                .await
            {
                Ok(response) => {
                    let response = response.serialize(&tag);
                    StatusResponse::completed(if !is_sort {
                        Command::Search(is_uid)
                    } else {
                        Command::Sort(is_uid)
                    })
                    .with_tag(tag)
                    .serialize(response)
                }
                Err(err) => {
                    if let Some(prev_saved_search) = prev_saved_search {
                        *mailbox.saved_search.lock() = prev_saved_search
                            .map_or(SavedSearch::None, |s| SavedSearch::Results { items: s });
                    }
                    return Err(err.id(tag));
                }
            };
            data.write_bytes(bytes).await
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn search(
        &self,
        arguments: Arguments,
        mailbox: Arc<SelectedMailbox>,
        results_tx: Option<watch::Sender<Arc<Vec<ImapId>>>>,
        prev_saved_search: Option<Option<Arc<Vec<ImapId>>>>,
        is_uid: bool,
    ) -> trc::Result<search::Response> {
        // Run query
        let (result_set, include_highest_modseq) = self
            .query(arguments.filter, &mailbox, &prev_saved_search)
            .await?;

        // Obtain modseq
        let highest_modseq = if include_highest_modseq {
            self.synchronize_messages(&mailbox)
                .await?
                .to_modseq()
                .into()
        } else {
            None
        };

        // Sort and map ids
        let mut min: Option<(u32, ImapId)> = None;
        let mut max: Option<(u32, ImapId)> = None;
        let mut total = 0;
        let results_len = result_set.results.len() as usize;
        let mut saved_results = if results_tx.is_some() {
            Some(Vec::with_capacity(results_len))
        } else {
            None
        };
        let mut imap_ids = Vec::with_capacity(results_len);
        let is_sort = if let Some(sort) = arguments.sort {
            mailbox.map_search_results(
                self.jmap
                    .core
                    .storage
                    .data
                    .sort(
                        result_set,
                        sort.into_iter()
                            .map(|item| match item.sort {
                                search::Sort::Arrival => {
                                    query::Comparator::field(Property::ReceivedAt, item.ascending)
                                }
                                search::Sort::Cc => {
                                    query::Comparator::field(Property::Cc, item.ascending)
                                }
                                search::Sort::Date => {
                                    query::Comparator::field(Property::SentAt, item.ascending)
                                }
                                search::Sort::From | search::Sort::DisplayFrom => {
                                    query::Comparator::field(Property::From, item.ascending)
                                }
                                search::Sort::Size => {
                                    query::Comparator::field(Property::Size, item.ascending)
                                }
                                search::Sort::Subject => {
                                    query::Comparator::field(Property::Subject, item.ascending)
                                }
                                search::Sort::To | search::Sort::DisplayTo => {
                                    query::Comparator::field(Property::To, item.ascending)
                                }
                            })
                            .collect::<Vec<_>>(),
                        Pagination::new(results_len, 0, None, 0),
                    )
                    .await
                    .caused_by(trc::location!())?
                    .ids
                    .into_iter()
                    .map(|id| id as u32),
                is_uid,
                arguments.result_options.contains(&ResultOption::Min),
                arguments.result_options.contains(&ResultOption::Max),
                &mut min,
                &mut max,
                &mut total,
                &mut imap_ids,
                &mut saved_results,
            );
            true
        } else {
            mailbox.map_search_results(
                result_set.results.into_iter(),
                is_uid,
                arguments.result_options.contains(&ResultOption::Min),
                arguments.result_options.contains(&ResultOption::Max),
                &mut min,
                &mut max,
                &mut total,
                &mut imap_ids,
                &mut saved_results,
            );
            imap_ids.sort_unstable();
            false
        };

        // Save results
        if let (Some(results_tx), Some(saved_results)) = (results_tx, saved_results) {
            let saved_results = Arc::new(saved_results);
            *mailbox.saved_search.lock() = SavedSearch::Results {
                items: saved_results.clone(),
            };
            results_tx.send(saved_results).ok();
        }

        // Build response
        Ok(Response {
            is_uid,
            min: min.map(|(id, _)| id),
            max: max.map(|(id, _)| id),
            count: if arguments.result_options.contains(&ResultOption::Count) {
                Some(total)
            } else {
                None
            },
            ids: if arguments.result_options.is_empty()
                || arguments.result_options.contains(&ResultOption::All)
            {
                imap_ids
            } else {
                vec![]
            },
            is_sort,
            is_esearch: arguments.is_esearch,
            highest_modseq,
        })
    }

    pub async fn query(
        &self,
        imap_filter: Vec<Filter>,
        mailbox: &SelectedMailbox,
        prev_saved_search: &Option<Option<Arc<Vec<ImapId>>>>,
    ) -> trc::Result<(ResultSet, bool)> {
        // Obtain message ids
        let mut filters = Vec::with_capacity(imap_filter.len() + 1);
        let message_ids = self
            .jmap
            .get_tag(
                mailbox.id.account_id,
                Collection::Email,
                Property::MailboxIds,
                mailbox.id.mailbox_id,
            )
            .await?
            .unwrap_or_default();
        filters.push(query::Filter::is_in_set(message_ids.clone()));

        // Convert query
        let mut include_highest_modseq = false;
        for filter_group in imap_filter.into_filter_group() {
            match filter_group {
                FilterGroup::Fts(conds) => {
                    let mut fts_filters = Vec::with_capacity(filters.len());
                    for cond in conds {
                        match cond {
                            search::Filter::Bcc(text) => {
                                fts_filters.push(FtsFilter::has_text(
                                    Field::Header(HeaderName::Bcc),
                                    text,
                                    Language::None,
                                ));
                            }
                            search::Filter::Body(text) => {
                                fts_filters.push(FtsFilter::has_text_detect(
                                    Field::Body,
                                    text,
                                    self.jmap.core.jmap.default_language,
                                ));
                            }
                            search::Filter::Cc(text) => {
                                fts_filters.push(FtsFilter::has_text(
                                    Field::Header(HeaderName::Cc),
                                    text,
                                    Language::None,
                                ));
                            }
                            search::Filter::From(text) => {
                                fts_filters.push(FtsFilter::has_text(
                                    Field::Header(HeaderName::From),
                                    text,
                                    Language::None,
                                ));
                            }
                            search::Filter::Header(header, value) => {
                                match HeaderName::parse(header) {
                                    Some(HeaderName::Other(header_name)) => {
                                        return Err(trc::Cause::Imap.into_err().details(format!(
                                            "Querying header '{header_name}' is not supported.",
                                        )));
                                    }
                                    Some(header_name) => {
                                        if !value.is_empty() {
                                            if matches!(
                                                header_name,
                                                HeaderName::MessageId
                                                    | HeaderName::InReplyTo
                                                    | HeaderName::References
                                                    | HeaderName::ResentMessageId
                                            ) {
                                                fts_filters.push(FtsFilter::has_keyword(
                                                    Field::Header(header_name),
                                                    value,
                                                ));
                                            } else {
                                                fts_filters.push(FtsFilter::has_text(
                                                    Field::Header(header_name),
                                                    value,
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
                            search::Filter::Subject(text) => {
                                fts_filters.push(FtsFilter::has_text_detect(
                                    Field::Header(HeaderName::Subject),
                                    text,
                                    self.jmap.core.jmap.default_language,
                                ));
                            }
                            search::Filter::Text(text) => {
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
                                    self.jmap.core.jmap.default_language,
                                ));
                                fts_filters.push(FtsFilter::has_text_detect(
                                    Field::Body,
                                    &text,
                                    self.jmap.core.jmap.default_language,
                                ));
                                fts_filters.push(FtsFilter::has_text_detect(
                                    Field::Attachment,
                                    text,
                                    self.jmap.core.jmap.default_language,
                                ));
                                fts_filters.push(FtsFilter::End);
                            }
                            search::Filter::To(text) => {
                                fts_filters.push(FtsFilter::has_text(
                                    Field::Header(HeaderName::To),
                                    text,
                                    Language::None,
                                ));
                            }
                            search::Filter::And => {
                                fts_filters.push(FtsFilter::And);
                            }
                            search::Filter::Or => {
                                fts_filters.push(FtsFilter::Or);
                            }
                            search::Filter::Not => {
                                fts_filters.push(FtsFilter::Not);
                            }
                            search::Filter::End => {
                                fts_filters.push(FtsFilter::End);
                            }
                            _ => (),
                        }
                    }

                    filters.push(query::Filter::is_in_set(
                        self.jmap
                            .fts_filter(mailbox.id.account_id, Collection::Email, fts_filters)
                            .await?,
                    ));
                }
                FilterGroup::Store(cond) => match cond {
                    search::Filter::Sequence(sequence, uid_filter) => {
                        let mut set = RoaringBitmap::new();
                        if let (Sequence::SavedSearch, Some(prev_saved_search)) =
                            (&sequence, &prev_saved_search)
                        {
                            if let Some(prev_saved_search) = prev_saved_search {
                                let state = mailbox.state.lock();
                                for imap_id in prev_saved_search.iter() {
                                    if let Some(id) = state.uid_to_id.get(&imap_id.uid) {
                                        set.insert(*id);
                                    }
                                }
                            } else {
                                return Err(trc::Cause::Imap
                                    .into_err()
                                    .details("No saved search found."));
                            }
                        } else {
                            for id in mailbox.sequence_to_ids(&sequence, uid_filter).await?.keys() {
                                set.insert(*id);
                            }
                        }
                        filters.push(query::Filter::is_in_set(set));
                    }
                    search::Filter::All => {
                        filters.push(query::Filter::is_in_set(message_ids.clone()));
                    }
                    search::Filter::Answered => {
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::Answered,
                        ));
                    }
                    search::Filter::Before(date) => {
                        filters.push(query::Filter::lt(Property::ReceivedAt, date as u64));
                    }
                    search::Filter::Deleted => {
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::Deleted,
                        ));
                    }
                    search::Filter::Draft => {
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::Draft,
                        ));
                    }
                    search::Filter::Flagged => {
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::Flagged,
                        ));
                    }
                    search::Filter::Keyword(keyword) => {
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::from(keyword),
                        ));
                    }
                    search::Filter::Larger(size) => {
                        filters.push(query::Filter::gt(Property::Size, size));
                    }
                    search::Filter::On(date) => {
                        filters.push(query::Filter::And);
                        filters.push(query::Filter::ge(Property::ReceivedAt, date as u64));
                        filters.push(query::Filter::lt(
                            Property::ReceivedAt,
                            (date + 86400) as u64,
                        ));
                        filters.push(query::Filter::End);
                    }
                    search::Filter::Seen => {
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::Seen,
                        ));
                    }
                    search::Filter::SentBefore(date) => {
                        filters.push(query::Filter::lt(Property::SentAt, date as u64));
                    }
                    search::Filter::SentOn(date) => {
                        filters.push(query::Filter::And);
                        filters.push(query::Filter::ge(Property::SentAt, date as u64));
                        filters.push(query::Filter::lt(Property::SentAt, (date + 86400) as u64));
                        filters.push(query::Filter::End);
                    }
                    search::Filter::SentSince(date) => {
                        filters.push(query::Filter::ge(Property::SentAt, date as u64));
                    }
                    search::Filter::Since(date) => {
                        filters.push(query::Filter::ge(Property::ReceivedAt, date as u64));
                    }
                    search::Filter::Smaller(size) => {
                        filters.push(query::Filter::lt(Property::Size, size));
                    }
                    search::Filter::Unanswered => {
                        filters.push(query::Filter::Not);
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::Answered,
                        ));
                        filters.push(query::Filter::End);
                    }
                    search::Filter::Undeleted => {
                        filters.push(query::Filter::Not);
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::Deleted,
                        ));
                        filters.push(query::Filter::End);
                    }
                    search::Filter::Undraft => {
                        filters.push(query::Filter::Not);
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::Draft,
                        ));
                        filters.push(query::Filter::End);
                    }
                    search::Filter::Unflagged => {
                        filters.push(query::Filter::Not);
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::Flagged,
                        ));
                        filters.push(query::Filter::End);
                    }
                    search::Filter::Unkeyword(keyword) => {
                        filters.push(query::Filter::Not);
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::from(keyword),
                        ));
                        filters.push(query::Filter::End);
                    }
                    search::Filter::Unseen => {
                        filters.push(query::Filter::Not);
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::Seen,
                        ));
                        filters.push(query::Filter::End);
                    }
                    search::Filter::And => {
                        filters.push(query::Filter::And);
                    }
                    search::Filter::Or => {
                        filters.push(query::Filter::Or);
                    }
                    search::Filter::Not => {
                        filters.push(query::Filter::Not);
                    }
                    search::Filter::End => {
                        filters.push(query::Filter::End);
                    }
                    search::Filter::Recent => {
                        //filters.push(query::Filter::is_in_set(self.get_recent(&mailbox.id)));
                    }
                    search::Filter::New => {
                        /*filters.push(query::Filter::And);
                        filters.push(query::Filter::is_in_set(self.get_recent(&mailbox.id)));
                        filters.push(query::Filter::Not);
                        filters.push(query::Filter::is_in_bitmap(
                            Property::Keywords,
                            Keyword::Seen,
                        ));
                        filters.push(query::Filter::End);
                        filters.push(query::Filter::End);*/
                    }
                    search::Filter::Old => {
                        /*filters.push(query::Filter::Not);
                        filters.push(query::Filter::is_in_set(self.get_recent(&mailbox.id)));
                        filters.push(query::Filter::End);*/
                    }
                    search::Filter::Older(secs) => {
                        filters.push(query::Filter::le(
                            Property::ReceivedAt,
                            now().saturating_sub(secs as u64),
                        ));
                    }
                    search::Filter::Younger(secs) => {
                        filters.push(query::Filter::ge(
                            Property::ReceivedAt,
                            now().saturating_sub(secs as u64),
                        ));
                    }
                    search::Filter::ModSeq((modseq, _)) => {
                        let mut set = RoaringBitmap::new();
                        for change in self
                            .jmap
                            .changes_(
                                mailbox.id.account_id,
                                Collection::Email,
                                Query::from_modseq(modseq),
                            )
                            .await?
                            .changes
                        {
                            let id = (change.unwrap_id() & u32::MAX as u64) as u32;
                            if message_ids.contains(id) {
                                set.insert(id);
                            }
                        }
                        filters.push(query::Filter::is_in_set(set));
                        include_highest_modseq = true;
                    }
                    search::Filter::EmailId(id) => {
                        if let Some(id) = Id::from_bytes(id.as_bytes()) {
                            filters.push(query::Filter::is_in_set(
                                RoaringBitmap::from_sorted_iter([id.document_id()]).unwrap(),
                            ));
                        } else {
                            return Err(trc::Cause::Imap
                                .into_err()
                                .details(format!("Failed to parse email id '{id}'.",)));
                        }
                    }
                    search::Filter::ThreadId(id) => {
                        if let Some(id) = Id::from_bytes(id.as_bytes()) {
                            filters.push(query::Filter::is_in_bitmap(
                                Property::ThreadId,
                                id.document_id(),
                            ));
                        } else {
                            return Err(trc::Cause::Imap
                                .into_err()
                                .details(format!("Failed to parse thread id '{id}'.",)));
                        }
                    }
                    _ => (),
                },
            }
        }

        // Run query
        self.jmap
            .filter(mailbox.id.account_id, Collection::Email, filters)
            .await
            .map(|res| (res, include_highest_modseq))
            .caused_by(trc::location!())
    }
}

impl SelectedMailbox {
    pub async fn get_saved_search(&self) -> Option<Arc<Vec<ImapId>>> {
        let mut rx = match &*self.saved_search.lock() {
            SavedSearch::InFlight { rx } => rx.clone(),
            SavedSearch::Results { items } => {
                return Some(items.clone());
            }
            SavedSearch::None => {
                return None;
            }
        };
        rx.changed().await.ok();
        let v = rx.borrow();
        Some(v.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn map_search_results(
        &self,
        ids: impl Iterator<Item = u32>,
        is_uid: bool,
        find_min: bool,
        find_max: bool,
        min: &mut Option<(u32, ImapId)>,
        max: &mut Option<(u32, ImapId)>,
        total: &mut u32,
        imap_ids: &mut Vec<u32>,
        saved_results: &mut Option<Vec<ImapId>>,
    ) {
        let state = self.state.lock();
        let find_min_or_max = find_min || find_max;
        for document_id in ids {
            if let Some((id, imap_id)) = state.map_result_id(document_id, is_uid) {
                if find_min_or_max {
                    if find_min {
                        if let Some((prev_min, _)) = min {
                            if id < *prev_min {
                                *min = Some((id, imap_id));
                            }
                        } else {
                            *min = Some((id, imap_id));
                        }
                    }
                    if find_max {
                        if let Some((prev_max, _)) = max {
                            if id > *prev_max {
                                *max = Some((id, imap_id));
                            }
                        } else {
                            *max = Some((id, imap_id));
                        }
                    }
                } else {
                    imap_ids.push(id);
                    if let Some(r) = saved_results.as_mut() {
                        r.push(imap_id)
                    }
                }
                *total += 1;
            }
        }
        if find_min || find_max {
            for (id, imap_id) in [min, max].into_iter().flatten() {
                imap_ids.push(*id);
                if let Some(r) = saved_results.as_mut() {
                    r.push(*imap_id)
                }
            }
        }
    }
}

impl MailboxState {
    pub fn map_result_id(&self, document_id: u32, is_uid: bool) -> Option<(u32, ImapId)> {
        if let Some(imap_id) = self.id_to_imap.get(&document_id) {
            Some((if is_uid { imap_id.uid } else { imap_id.seqnum }, *imap_id))
        } else if is_uid {
            self.next_state.as_ref().and_then(|s| {
                s.next_state
                    .id_to_imap
                    .get(&document_id)
                    .map(|imap_id| (imap_id.uid, *imap_id))
            })
        } else {
            None
        }
    }
}

impl SavedSearch {
    pub async fn unwrap(&self) -> Option<Arc<Vec<ImapId>>> {
        match self {
            SavedSearch::InFlight { rx } => {
                let mut rx = rx.clone();
                rx.changed().await.ok();
                let v = rx.borrow();
                Some(v.clone())
            }
            SavedSearch::Results { items } => Some(items.clone()),
            SavedSearch::None => None,
        }
    }
}
