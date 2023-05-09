use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use jmap_proto::error::request::{RequestError, RequestLimitError};
use mail_send::mail_auth::common::lru::DnsCache;
use store::parking_lot::Mutex;
use utils::listener::limiter::{ConcurrencyLimiter, InFlight, RateLimiter};

use crate::{JMAP, SUPERUSER_ID};

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
                    self.config.rate_authenticated.period.as_secs(),
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
                    self.config.rate_anonymous.period.as_secs(),
                ),
                auth_limiter: RateLimiter::new(
                    self.config.rate_authenticate_req.requests,
                    self.config.rate_authenticate_req.period.as_secs(),
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

    pub fn is_account_allowed(&self, account_id: u32) -> Result<InFlight, RequestError> {
        if account_id != SUPERUSER_ID {
            let limiter_ = self.get_authenticated_limiter(account_id);
            let mut limiter = limiter_.lock();

            if limiter.request_limiter.is_allowed() {
                if let Some(in_flight_request) = limiter.concurrent_requests.is_allowed() {
                    Ok(in_flight_request)
                } else {
                    Err(RequestError::limit(RequestLimitError::Concurrent))
                }
            } else {
                Err(RequestError::too_many_requests())
            }
        } else {
            Ok(InFlight::default())
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
