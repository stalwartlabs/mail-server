/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::borrow::Cow;

use mail_send::Credentials;
use smtp_proto::{Response, Severity};
use utils::config::ServerProtocol;

use crate::{
    config::RelayHost,
    queue::{DeliveryAttempt, Error, ErrorDetails, HostResponse, Message, Status},
};

pub mod dane;
pub mod delivery;
pub mod lookup;
pub mod mta_sts;
pub mod session;

impl Status<(), Error> {
    pub fn from_smtp_error(hostname: &str, command: &str, err: mail_send::Error) -> Self {
        match err {
            mail_send::Error::Io(_)
            | mail_send::Error::Tls(_)
            | mail_send::Error::Base64(_)
            | mail_send::Error::UnparseableReply
            | mail_send::Error::AuthenticationFailed(_)
            | mail_send::Error::MissingCredentials
            | mail_send::Error::MissingMailFrom
            | mail_send::Error::MissingRcptTo
            | mail_send::Error::Timeout => {
                Status::TemporaryFailure(Error::ConnectionError(ErrorDetails {
                    entity: hostname.to_string(),
                    details: err.to_string(),
                }))
            }

            mail_send::Error::UnexpectedReply(reply) => {
                let details = ErrorDetails {
                    entity: hostname.to_string(),
                    details: command.trim().to_string(),
                };
                if reply.severity() == Severity::PermanentNegativeCompletion {
                    Status::PermanentFailure(Error::UnexpectedResponse(HostResponse {
                        hostname: details,
                        response: reply,
                    }))
                } else {
                    Status::TemporaryFailure(Error::UnexpectedResponse(HostResponse {
                        hostname: details,
                        response: reply,
                    }))
                }
            }

            mail_send::Error::Auth(_)
            | mail_send::Error::UnsupportedAuthMechanism
            | mail_send::Error::InvalidTLSName
            | mail_send::Error::MissingStartTls => {
                Status::PermanentFailure(Error::ConnectionError(ErrorDetails {
                    entity: hostname.to_string(),
                    details: err.to_string(),
                }))
            }
        }
    }

    pub fn from_starttls_error(hostname: &str, response: Option<Response<String>>) -> Self {
        let entity = hostname.to_string();
        if let Some(response) = response {
            let hostname = ErrorDetails {
                entity,
                details: "STARTTLS".to_string(),
            };

            if response.severity() == Severity::PermanentNegativeCompletion {
                Status::PermanentFailure(Error::UnexpectedResponse(HostResponse {
                    hostname,
                    response,
                }))
            } else {
                Status::TemporaryFailure(Error::UnexpectedResponse(HostResponse {
                    hostname,
                    response,
                }))
            }
        } else {
            Status::PermanentFailure(Error::TlsError(ErrorDetails {
                entity,
                details: "STARTTLS not advertised by host.".to_string(),
            }))
        }
    }

    pub fn from_tls_error(hostname: &str, err: mail_send::Error) -> Self {
        match err {
            mail_send::Error::InvalidTLSName => {
                Status::PermanentFailure(Error::TlsError(ErrorDetails {
                    entity: hostname.to_string(),
                    details: "Invalid hostname".to_string(),
                }))
            }
            mail_send::Error::Timeout => Status::TemporaryFailure(Error::TlsError(ErrorDetails {
                entity: hostname.to_string(),
                details: "TLS handshake timed out".to_string(),
            })),
            mail_send::Error::Tls(err) => Status::TemporaryFailure(Error::TlsError(ErrorDetails {
                entity: hostname.to_string(),
                details: format!("Handshake failed: {err}"),
            })),
            mail_send::Error::Io(err) => Status::TemporaryFailure(Error::TlsError(ErrorDetails {
                entity: hostname.to_string(),
                details: format!("I/O error: {err}"),
            })),
            _ => Status::PermanentFailure(Error::TlsError(ErrorDetails {
                entity: hostname.to_string(),
                details: "Other TLS error".to_string(),
            })),
        }
    }

    pub fn timeout(hostname: &str, stage: &str) -> Self {
        Status::TemporaryFailure(Error::ConnectionError(ErrorDetails {
            entity: hostname.to_string(),
            details: format!("Timeout while {stage}"),
        }))
    }
}

impl From<mail_auth::Error> for Status<(), Error> {
    fn from(err: mail_auth::Error) -> Self {
        match &err {
            mail_auth::Error::DnsRecordNotFound(code) => {
                Status::PermanentFailure(Error::DnsError(format!("Domain not found: {code:?}")))
            }
            _ => Status::TemporaryFailure(Error::DnsError(err.to_string())),
        }
    }
}

impl From<mta_sts::Error> for Status<(), Error> {
    fn from(err: mta_sts::Error) -> Self {
        match &err {
            mta_sts::Error::Dns(err) => match err {
                mail_auth::Error::DnsRecordNotFound(code) => Status::PermanentFailure(
                    Error::MtaStsError(format!("Record not found: {code:?}")),
                ),
                mail_auth::Error::InvalidRecordType => Status::PermanentFailure(
                    Error::MtaStsError("Failed to parse MTA-STS DNS record.".to_string()),
                ),
                _ => {
                    Status::TemporaryFailure(Error::MtaStsError(format!("DNS lookup error: {err}")))
                }
            },
            mta_sts::Error::Http(err) => {
                if err.is_timeout() {
                    Status::TemporaryFailure(Error::MtaStsError(
                        "Timeout fetching policy.".to_string(),
                    ))
                } else if err.is_connect() {
                    Status::TemporaryFailure(Error::MtaStsError(
                        "Could not reach policy host.".to_string(),
                    ))
                } else if err.is_status()
                    & err
                        .status()
                        .map_or(false, |s| s == reqwest::StatusCode::NOT_FOUND)
                {
                    Status::PermanentFailure(Error::MtaStsError("Policy not found.".to_string()))
                } else {
                    Status::TemporaryFailure(Error::MtaStsError(
                        "Failed to fetch policy.".to_string(),
                    ))
                }
            }
            mta_sts::Error::InvalidPolicy(err) => Status::PermanentFailure(Error::MtaStsError(
                format!("Failed to parse policy: {err}"),
            )),
        }
    }
}

impl From<Box<Message>> for DeliveryAttempt {
    fn from(message: Box<Message>) -> Self {
        DeliveryAttempt {
            span: tracing::info_span!(
                "delivery",
                "id" = message.id,
                "return_path" = if !message.return_path.is_empty() {
                    message.return_path.as_ref()
                } else {
                    "<>"
                },
                "nrcpt" = message.recipients.len(),
                "size" = message.size
            ),
            in_flight: Vec::new(),
            message,
        }
    }
}

enum RemoteHost<'x> {
    Relay(&'x RelayHost),
    MX(&'x str),
}

impl<'x> RemoteHost<'x> {
    #[inline(always)]
    fn hostname(&self) -> &str {
        match self {
            RemoteHost::MX(host) => {
                if let Some(host) = host.strip_suffix('.') {
                    host
                } else {
                    host
                }
            }
            RemoteHost::Relay(host) => host.address.as_str(),
        }
    }

    #[inline(always)]
    fn fqdn_hostname(&self) -> Cow<'_, str> {
        let host = match self {
            RemoteHost::MX(host) => host,
            RemoteHost::Relay(host) => host.address.as_str(),
        };
        if !host.ends_with('.') {
            format!("{host}.").into()
        } else {
            (*host).into()
        }
    }

    #[inline(always)]
    fn port(&self) -> u16 {
        match self {
            #[cfg(feature = "test_mode")]
            RemoteHost::MX(_) => 9925,
            #[cfg(not(feature = "test_mode"))]
            RemoteHost::MX(_) => 25,
            RemoteHost::Relay(host) => host.port,
        }
    }

    #[inline(always)]
    fn credentials(&self) -> Option<&Credentials<String>> {
        match self {
            RemoteHost::MX(_) => None,
            RemoteHost::Relay(host) => host.auth.as_ref(),
        }
    }

    #[inline(always)]
    fn allow_invalid_certs(&self) -> bool {
        #[cfg(feature = "test_mode")]
        {
            true
        }
        #[cfg(not(feature = "test_mode"))]
        match self {
            RemoteHost::MX(_) => false,
            RemoteHost::Relay(host) => host.tls_allow_invalid_certs,
        }
    }

    #[inline(always)]
    fn implicit_tls(&self) -> bool {
        match self {
            RemoteHost::MX(_) => false,
            RemoteHost::Relay(host) => host.tls_implicit,
        }
    }

    #[inline(always)]
    fn is_smtp(&self) -> bool {
        match self {
            RemoteHost::MX(_) => true,
            RemoteHost::Relay(host) => host.protocol == ServerProtocol::Smtp,
        }
    }
}
