use jmap_proto::{
    error::method::MethodError,
    method::get::{GetRequest, GetResponse, RequestArguments},
    object::Object,
    types::{collection::Collection, id::Id, property::Property},
};
use store::query::{sort::Pagination, Comparator, ResultSet};

use crate::JMAP;

impl JMAP {
    pub async fn thread_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> Result<GetResponse, MethodError> {
        let account_id = request.account_id.document_id();
        let ids = if let Some(ids) = request.unwrap_ids(self.config.get_max_objects)? {
            ids
        } else {
            self.get_document_ids(account_id, Collection::Thread)
                .await?
                .unwrap_or_default()
                .into_iter()
                .take(self.config.get_max_objects)
                .map(Into::into)
                .collect()
        };
        let add_email_ids = request
            .unwrap_properties()
            .map_or(true, |properties| properties.contains(&Property::EmailIds));
        let mut response = GetResponse {
            account_id: Some(request.account_id),
            state: self.get_state(account_id, Collection::Thread).await?,
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
                        self.store
                            .sort(
                                ResultSet::new(account_id, Collection::Email, document_ids.clone()),
                                vec![Comparator::ascending(Property::ReceivedAt)],
                                Pagination::new(
                                    document_ids.len() as usize,
                                    0,
                                    None,
                                    0,
                                    None,
                                    false,
                                ),
                            )
                            .await
                            .map_err(|err| {
                                tracing::error!(event = "error",
                                                context = "store",
                                                account_id = account_id,
                                                collection = "email",
                                                error = ?err,
                                                "Thread emailIds sort failed");
                                MethodError::ServerPartialFail
                            })?
                            .ids
                            .into_iter()
                            .map(|id| Id::from_parts(thread_id, id as u32))
                            .collect::<Vec<_>>(),
                    );
                }
                response.list.push(thread);
            } else {
                response.not_found.push(id);
            }
        }

        Ok(response)
    }
}
