/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::StateManager;
use common::Server;
use email::cache::MessageCacheFetch;
use jmap_proto::{
    method::get::{GetRequest, GetResponse, RequestArguments},
    types::{
        collection::{Collection, SyncCollection},
        id::Id,
        property::Property,
        value::Object,
    },
};
use std::future::Future;
use store::{
    ahash::AHashMap,
    query::{Comparator, ResultSet, sort::Pagination},
    roaring::RoaringBitmap,
};
use trc::AddContext;

pub trait ThreadGet: Sync + Send {
    fn thread_get(
        &self,
        request: GetRequest<RequestArguments>,
    ) -> impl Future<Output = trc::Result<GetResponse>> + Send;
}

impl ThreadGet for Server {
    async fn thread_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> trc::Result<GetResponse> {
        let account_id = request.account_id.document_id();
        let mut thread_map: AHashMap<u32, RoaringBitmap> = AHashMap::with_capacity(32);
        for item in &self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?
            .emails
            .items
        {
            thread_map
                .entry(item.thread_id)
                .or_default()
                .insert(item.document_id);
        }

        let ids = if let Some(ids) = request.unwrap_ids(self.core.jmap.get_max_objects)? {
            ids
        } else {
            thread_map
                .keys()
                .copied()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect()
        };
        let add_email_ids = request
            .properties
            .is_none_or(|p| p.unwrap().contains(&Property::EmailIds));
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self
                .get_state(account_id, SyncCollection::Thread)
                .await?
                .into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            let thread_id = id.document_id();
            if let Some(document_ids) = thread_map.remove(&thread_id) {
                let mut thread = Object::with_capacity(2).with_property(Property::Id, id);
                if add_email_ids {
                    let doc_count = document_ids.len() as usize;
                    thread.append(
                        Property::EmailIds,
                        self.core
                            .storage
                            .data
                            .sort(
                                ResultSet::new(account_id, Collection::Email, document_ids),
                                vec![Comparator::ascending(Property::ReceivedAt)],
                                Pagination::new(doc_count, 0, None, 0),
                            )
                            .await
                            .caused_by(trc::location!())?
                            .ids
                            .into_iter()
                            .map(|id| Id::from_parts(thread_id, id as u32))
                            .collect::<Vec<_>>(),
                    );
                }
                response.list.push(thread);
            } else {
                response.not_found.push(id.into());
            }
        }

        Ok(response)
    }
}
