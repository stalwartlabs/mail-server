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

use jmap_proto::error::request::{RequestError, RequestLimitError};
use utils::listener::limiter::{ConcurrencyLimiter, InFlight, RateLimiter};

use crate::JMAP;

use super::AccessToken;

pub struct AuthenticatedLimiter {
    pub request_limiter: RateLimiter,
    pub concurrent_requests: ConcurrencyLimiter,
    pub concurrent_uploads: ConcurrencyLimiter,
}

#[derive(Debug)]
pub struct AnonymousLimiter {
    request_limiter: RateLimiter,
    auth_limiter: RateLimiter,
}

impl JMAP {
    pub fn get_authenticated_limiter(&self, account_id: u32) -> Arc<AuthenticatedLimiter> {
        self.rate_limit_auth
            .get(&account_id)
            .map(|limiter| limiter.clone())
            .unwrap_or_else(|| {
                let limiter = Arc::new(AuthenticatedLimiter {
                    request_limiter: RateLimiter::new(&self.config.rate_authenticated),
                    concurrent_requests: ConcurrencyLimiter::new(
                        self.config.request_max_concurrent,
                    ),
                    concurrent_uploads: ConcurrencyLimiter::new(self.config.upload_max_concurrent),
                });
                self.rate_limit_auth.insert(account_id, limiter.clone());
                limiter
            })
    }

    pub fn get_anonymous_limiter(&self, addr: &IpAddr) -> Arc<AnonymousLimiter> {
        self.rate_limit_unauth
            .get(addr)
            .map(|limiter| limiter.clone())
            .unwrap_or_else(|| {
                let limiter = Arc::new(AnonymousLimiter {
                    request_limiter: RateLimiter::new(&self.config.rate_anonymous),
                    auth_limiter: RateLimiter::new(&self.config.rate_authenticate_req),
                });
                self.rate_limit_unauth.insert(*addr, limiter.clone());
                limiter
            })
    }

    pub fn is_account_allowed(&self, access_token: &AccessToken) -> Result<InFlight, RequestError> {
        let limiter = self.get_authenticated_limiter(access_token.primary_id());

        if limiter
            .request_limiter
            .is_allowed(&self.config.rate_authenticated)
        {
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

    pub fn is_anonymous_allowed(&self, addr: &IpAddr) -> Result<(), RequestError> {
        if self
            .get_anonymous_limiter(addr)
            .request_limiter
            .is_allowed(&self.config.rate_anonymous)
        {
            Ok(())
        } else {
            Err(RequestError::too_many_requests())
        }
    }

    pub fn is_upload_allowed(&self, access_token: &AccessToken) -> Result<InFlight, RequestError> {
        if let Some(in_flight_request) = self
            .get_authenticated_limiter(access_token.primary_id())
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

    pub fn is_auth_allowed_soft(&self, addr: &IpAddr) -> Result<(), RequestError> {
        match self.rate_limit_unauth.get(addr) {
            Some(limiter)
                if !limiter
                    .auth_limiter
                    .is_allowed_soft(&self.config.rate_authenticate_req) =>
            {
                Err(RequestError::too_many_auth_attempts())
            }
            _ => Ok(()),
        }
    }

    pub fn is_auth_allowed_hard(&self, addr: &IpAddr) -> Result<(), RequestError> {
        if self
            .get_anonymous_limiter(addr)
            .auth_limiter
            .is_allowed(&self.config.rate_authenticate_req)
        {
            Ok(())
        } else {
            Err(RequestError::too_many_auth_attempts())
        }
    }
}

impl AuthenticatedLimiter {
    pub fn is_active(&self) -> bool {
        self.request_limiter.is_active()
            || self.concurrent_requests.is_active()
            || self.concurrent_uploads.is_active()
    }
}

impl AnonymousLimiter {
    pub fn is_active(&self) -> bool {
        self.request_limiter.is_active() || self.auth_limiter.is_active()
    }
}
