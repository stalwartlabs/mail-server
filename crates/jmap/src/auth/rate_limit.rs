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

use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use jmap_proto::error::request::{RequestError, RequestLimitError};
use mail_send::mail_auth::common::lru::DnsCache;
use store::parking_lot::Mutex;
use utils::listener::limiter::{ConcurrencyLimiter, InFlight, RateLimiter};

use crate::JMAP;

use super::AccessToken;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum RemoteAddress {
    IpAddress(IpAddr),
    IpAddressFwd(String),
}

pub struct AuthenticatedLimiter {
    request_limiter: RateLimiter,
    concurrent_requests: ConcurrencyLimiter,
    concurrent_uploads: ConcurrencyLimiter,
}

#[derive(Debug)]
pub struct AnonymousLimiter {
    request_limiter: RateLimiter,
    auth_limiter: RateLimiter,
}

impl JMAP {
    pub fn get_authenticated_limiter(&self, account_id: u32) -> Arc<Mutex<AuthenticatedLimiter>> {
        self.rate_limit_auth.get(&account_id).unwrap_or_else(|| {
            let limiter = Arc::new(Mutex::new(AuthenticatedLimiter {
                request_limiter: RateLimiter::new(
                    self.config.rate_authenticated.requests,
                    self.config.rate_authenticated.period,
                ),
                concurrent_requests: ConcurrencyLimiter::new(self.config.request_max_concurrent),
                concurrent_uploads: ConcurrencyLimiter::new(
                    self.config.upload_max_concurrent as u64,
                ),
            }));
            self.rate_limit_auth.insert(
                account_id,
                limiter.clone(),
                Instant::now() + self.config.session_cache_ttl,
            );
            limiter
        })
    }

    pub fn get_anonymous_limiter(&self, addr: RemoteAddress) -> Arc<Mutex<AnonymousLimiter>> {
        self.rate_limit_unauth.get(&addr).unwrap_or_else(|| {
            let limiter = Arc::new(Mutex::new(AnonymousLimiter {
                request_limiter: RateLimiter::new(
                    self.config.rate_anonymous.requests,
                    self.config.rate_anonymous.period,
                ),
                auth_limiter: RateLimiter::new(
                    self.config.rate_authenticate_req.requests,
                    self.config.rate_authenticate_req.period,
                ),
            }));
            self.rate_limit_unauth.insert(
                addr,
                limiter.clone(),
                Instant::now() + Duration::from_secs(86400),
            );
            limiter
        })
    }

    pub fn is_account_allowed(&self, access_token: &AccessToken) -> Result<InFlight, RequestError> {
        let limiter_ = self.get_authenticated_limiter(access_token.primary_id());
        let mut limiter = limiter_.lock();

        if limiter.request_limiter.is_allowed() {
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

    pub fn is_anonymous_allowed(&self, addr: RemoteAddress) -> Result<(), RequestError> {
        if self
            .get_anonymous_limiter(addr)
            .lock()
            .request_limiter
            .is_allowed()
        {
            Ok(())
        } else {
            Err(RequestError::too_many_requests())
        }
    }

    pub fn is_upload_allowed(&self, access_token: &AccessToken) -> Result<InFlight, RequestError> {
        if let Some(in_flight_request) = self
            .get_authenticated_limiter(access_token.primary_id())
            .lock()
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

    pub fn is_auth_allowed(&self, addr: RemoteAddress) -> Result<(), RequestError> {
        if self
            .get_anonymous_limiter(addr)
            .lock()
            .auth_limiter
            .is_allowed()
        {
            Ok(())
        } else {
            Err(RequestError::too_many_auth_attempts())
        }
    }
}
