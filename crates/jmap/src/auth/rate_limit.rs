/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use std::{net::IpAddr, sync::Arc};

use common::listener::limiter::{ConcurrencyLimiter, InFlight};
use jmap_proto::error::request::{RequestError, RequestLimitError};

use crate::JMAP;

use super::AccessToken;

pub struct ConcurrencyLimiters {
    pub concurrent_requests: ConcurrencyLimiter,
    pub concurrent_uploads: ConcurrencyLimiter,
}

impl JMAP {
    pub fn get_concurrency_limiter(&self, account_id: u32) -> Arc<ConcurrencyLimiters> {
        self.inner
            .concurrency_limiter
            .get(&account_id)
            .map(|limiter| limiter.clone())
            .unwrap_or_else(|| {
                let limiter = Arc::new(ConcurrencyLimiters {
                    concurrent_requests: ConcurrencyLimiter::new(
                        self.core.jmap.request_max_concurrent,
                    ),
                    concurrent_uploads: ConcurrencyLimiter::new(
                        self.core.jmap.upload_max_concurrent,
                    ),
                });
                self.inner
                    .concurrency_limiter
                    .insert(account_id, limiter.clone());
                limiter
            })
    }

    pub async fn is_account_allowed(
        &self,
        access_token: &AccessToken,
    ) -> Result<InFlight, RequestError> {
        let limiter = self.get_concurrency_limiter(access_token.primary_id());
        let is_rate_allowed = if let Some(rate) = &self.core.jmap.rate_authenticated {
            self.core
                .storage
                .lookup
                .is_rate_allowed(
                    format!("j:{}", access_token.primary_id).as_bytes(),
                    rate,
                    false,
                )
                .await
                .map_err(|_| RequestError::internal_server_error())?
                .is_none()
        } else {
            true
        };

        if is_rate_allowed {
            if let Some(in_flight_request) = limiter.concurrent_requests.is_allowed() {
                Ok(in_flight_request)
            } else if access_token.is_super_user() {
                Ok(InFlight::default())
            } else {
                Err(RequestError::limit(RequestLimitError::ConcurrentRequest))
            }
        } else if access_token.is_super_user() {
            Ok(InFlight::default())
        } else {
            Err(RequestError::too_many_requests())
        }
    }

    pub async fn is_anonymous_allowed(&self, addr: &IpAddr) -> Result<(), RequestError> {
        if let Some(rate) = &self.core.jmap.rate_anonymous {
            if self
                .core
                .storage
                .lookup
                .is_rate_allowed(format!("jreq:{}", addr).as_bytes(), rate, false)
                .await
                .map_err(|_| RequestError::internal_server_error())?
                .is_some()
            {
                return Err(RequestError::too_many_requests());
            }
        }
        Ok(())
    }

    pub fn is_upload_allowed(&self, access_token: &AccessToken) -> Result<InFlight, RequestError> {
        if let Some(in_flight_request) = self
            .get_concurrency_limiter(access_token.primary_id())
            .concurrent_uploads
            .is_allowed()
        {
            Ok(in_flight_request)
        } else if access_token.is_super_user() {
            Ok(InFlight::default())
        } else {
            Err(RequestError::limit(RequestLimitError::ConcurrentUpload))
        }
    }

    pub async fn is_auth_allowed_soft(&self, addr: &IpAddr) -> Result<(), RequestError> {
        if let Some(rate) = &self.core.jmap.rate_authenticate_req {
            if self
                .core
                .storage
                .lookup
                .is_rate_allowed(format!("jauth:{}", addr).as_bytes(), rate, true)
                .await
                .map_err(|_| RequestError::internal_server_error())?
                .is_some()
            {
                return Err(RequestError::too_many_auth_attempts());
            }
        }
        Ok(())
    }

    pub async fn is_auth_allowed_hard(&self, addr: &IpAddr) -> Result<(), RequestError> {
        if let Some(rate) = &self.core.jmap.rate_authenticate_req {
            if self
                .core
                .storage
                .lookup
                .is_rate_allowed(format!("jauth:{}", addr).as_bytes(), rate, false)
                .await
                .map_err(|_| RequestError::internal_server_error())?
                .is_some()
            {
                return Err(RequestError::too_many_auth_attempts());
            }
        }
        Ok(())
    }
}

impl ConcurrencyLimiters {
    pub fn is_active(&self) -> bool {
        self.concurrent_requests.is_active() || self.concurrent_uploads.is_active()
    }
}
