/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use crate::{
    KV_RATE_LIMIT_HTTP_ANONYMOUS, KV_RATE_LIMIT_HTTP_AUTHENTICATED, Server, ip_to_bytes,
    listener::limiter::{InFlight, LimiterResult},
};
use directory::Permission;
use trc::AddContext;

use crate::auth::AccessToken;

impl Server {
    pub async fn is_http_authenticated_request_allowed(
        &self,
        access_token: &AccessToken,
    ) -> trc::Result<Option<InFlight>> {
        let is_rate_allowed = if let Some(rate) = &self.core.jmap.rate_authenticated {
            self.core
                .storage
                .lookup
                .is_rate_allowed(
                    KV_RATE_LIMIT_HTTP_AUTHENTICATED,
                    &access_token.primary_id.to_be_bytes(),
                    rate,
                    false,
                )
                .await
                .caused_by(trc::location!())?
                .is_none()
        } else {
            true
        };

        if is_rate_allowed {
            match access_token.is_http_request_allowed() {
                LimiterResult::Allowed(in_flight) => Ok(Some(in_flight)),
                LimiterResult::Forbidden => {
                    if access_token.has_permission(Permission::UnlimitedRequests) {
                        Ok(None)
                    } else {
                        Err(trc::LimitEvent::ConcurrentRequest.into_err())
                    }
                }
                LimiterResult::Disabled => Ok(None),
            }
        } else if access_token.has_permission(Permission::UnlimitedRequests) {
            Ok(None)
        } else {
            Err(trc::LimitEvent::TooManyRequests.into_err())
        }
    }

    pub async fn is_http_anonymous_request_allowed(&self, addr: &IpAddr) -> trc::Result<()> {
        if let Some(rate) = &self.core.jmap.rate_anonymous {
            if !self.is_ip_allowed(addr)
                && self
                    .core
                    .storage
                    .lookup
                    .is_rate_allowed(
                        KV_RATE_LIMIT_HTTP_ANONYMOUS,
                        &ip_to_bytes(addr),
                        rate,
                        false,
                    )
                    .await
                    .caused_by(trc::location!())?
                    .is_some()
            {
                return Err(trc::LimitEvent::TooManyRequests.into_err());
            }
        }
        Ok(())
    }

    pub fn is_upload_allowed(&self, access_token: &AccessToken) -> trc::Result<Option<InFlight>> {
        match access_token.is_upload_allowed() {
            LimiterResult::Allowed(in_flight) => Ok(Some(in_flight)),
            LimiterResult::Forbidden => {
                if access_token.has_permission(Permission::UnlimitedRequests) {
                    Ok(None)
                } else {
                    Err(trc::LimitEvent::ConcurrentUpload.into_err())
                }
            }
            LimiterResult::Disabled => Ok(None),
        }
    }
}
