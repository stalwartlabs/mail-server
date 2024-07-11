/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    method::get::{GetRequest, GetResponse, RequestArguments},
    object::Object,
    types::{collection::Collection, id::Id, property::Property},
};
use store::query::{sort::Pagination, Comparator, ResultSet};
use trc::AddContext;

use crate::JMAP;

impl JMAP {
    pub async fn thread_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> trc::Result<GetResponse> {
        let account_id = request.account_id.document_id();
        let ids = if let Some(ids) = request.unwrap_ids(self.core.jmap.get_max_objects)? {
            ids
        } else {
            self.get_document_ids(account_id, Collection::Thread)
                .await?
                .unwrap_or_default()
                .into_iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect()
        };
        let add_email_ids = request
            .properties
            .map_or(true, |p| p.unwrap().contains(&Property::EmailIds));
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self.get_state(account_id, Collection::Thread).await?.into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            let thread_id = id.document_id();
            if let Some(document_ids) = self
                .get_tag(account_id, Collection::Email, Property::ThreadId, thread_id)
                .await?
            {
                let mut thread = Object::with_capacity(2).with_property(Property::Id, id);
                if add_email_ids {
                    thread.append(
                        Property::EmailIds,
                        self.core
                            .storage
                            .data
                            .sort(
                                ResultSet::new(account_id, Collection::Email, document_ids.clone()),
                                vec![Comparator::ascending(Property::ReceivedAt)],
                                Pagination::new(document_ids.len() as usize, 0, None, 0),
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
