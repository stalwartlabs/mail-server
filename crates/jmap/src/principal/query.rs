/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

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
                        .directory
                        .principal(&name)
                        .await
                        .map_err(|_| MethodError::ServerPartialFail)?
                    {
                        let account_id = self.get_account_id(&principal.name).await?;
                        if is_set || result_set.results.contains(account_id) {
                            result_set.results =
                                RoaringBitmap::from_sorted_iter([account_id]).unwrap();
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
                    for name in self
                        .directory
                        .names_by_email(&email)
                        .await
                        .map_err(|_| MethodError::ServerPartialFail)?
                    {
                        ids.insert(self.get_account_id(&name).await?);
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
