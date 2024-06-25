/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use directory::QueryBy;
use jmap_proto::{
    error::method::MethodError,
    method::query::{Filter, QueryRequest, QueryResponse, RequestArguments},
    types::collection::Collection,
};
use store::{query::ResultSet, roaring::RoaringBitmap};

use crate::JMAP;

impl JMAP {
    pub async fn principal_query(
        &self,
        mut request: QueryRequest<RequestArguments>,
    ) -> Result<QueryResponse, MethodError> {
        let account_id = request.account_id.document_id();
        let mut result_set = ResultSet {
            account_id,
            collection: Collection::Principal.into(),
            results: RoaringBitmap::new(),
        };
        let mut is_set = true;

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Name(name) => {
                    if let Some(principal) = self
                        .core
                        .storage
                        .directory
                        .query(QueryBy::Name(name.as_str()), false)
                        .await
                        .map_err(|_| MethodError::ServerPartialFail)?
                    {
                        if is_set || result_set.results.contains(principal.id) {
                            result_set.results =
                                RoaringBitmap::from_sorted_iter([principal.id]).unwrap();
                        } else {
                            result_set.results = RoaringBitmap::new();
                        }
                    } else {
                        result_set.results = RoaringBitmap::new();
                    }
                    is_set = false;
                }
                Filter::Email(email) => {
                    let mut ids = RoaringBitmap::new();
                    for id in self
                        .core
                        .email_to_ids(&self.core.storage.directory, &email)
                        .await
                        .map_err(|_| MethodError::ServerPartialFail)?
                    {
                        ids.insert(id);
                    }
                    if is_set {
                        result_set.results = ids;
                        is_set = false;
                    } else {
                        result_set.results &= ids;
                    }
                }
                Filter::Type(_) => {}
                other => return Err(MethodError::UnsupportedFilter(other.to_string())),
            }
        }

        if is_set {
            result_set.results = self
                .get_document_ids(u32::MAX, Collection::Principal)
                .await?
                .unwrap_or_default();
        }

        let (response, paginate) = self.build_query_response(&result_set, &request).await?;

        if let Some(paginate) = paginate {
            self.sort(result_set, Vec::new(), paginate, response).await
        } else {
            Ok(response)
        }
    }
}
