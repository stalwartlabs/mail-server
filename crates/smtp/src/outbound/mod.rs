/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use common::config::{
    server::ServerProtocol,
    smtp::queue::{RelayHost, RequireOptional},
};
use mail_send::Credentials;
use smtp_proto::{Response, Severity};

use crate::queue::{
    spool::QueueEventLock, DeliveryAttempt, Error, ErrorDetails, HostResponse, Status,
};

pub mod client;
pub mod dane;
pub mod delivery;
pub mod local;
pub mod lookup;
pub mod mta_sts;
pub mod session;

#[derive(Debug, Clone, Copy, Default)]
pub struct TlsStrategy {
    pub dane: RequireOptional,
    pub mta_sts: RequireOptional,
    pub tls: RequireOptional,
}

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

    pub fn local_error() -> Self {
        Status::TemporaryFailure(Error::ConnectionError(ErrorDetails {
            entity: "localhost".to_string(),
            details: "Could not deliver message locally.".to_string(),
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

impl DeliveryAttempt {
    pub fn new(event: QueueEventLock) -> Self {
        DeliveryAttempt {
            in_flight: Vec::new(),
            event,
        }
    }
}

#[derive(Debug)]
pub enum NextHop<'x> {
    Relay(&'x RelayHost),
    MX(&'x str),
}

impl<'x> NextHop<'x> {
    #[inline(always)]
    fn hostname(&self) -> &str {
        match self {
            NextHop::MX(host) => {
                if let Some(host) = host.strip_suffix('.') {
                    host
                } else {
                    host
                }
            }
            NextHop::Relay(host) => host.address.as_str(),
        }
    }

    #[inline(always)]
    fn fqdn_hostname(&self) -> Cow<'_, str> {
        match self {
            NextHop::MX(host) => {
                if !host.ends_with('.') {
                    format!("{host}.").into()
                } else {
                    (*host).into()
                }
            }
            NextHop::Relay(host) => host.address.as_str().into(),
        }
    }

    #[inline(always)]
    fn port(&self) -> u16 {
        match self {
            #[cfg(feature = "test_mode")]
            NextHop::MX(_) => 9925,
            #[cfg(not(feature = "test_mode"))]
            NextHop::MX(_) => 25,
            NextHop::Relay(host) => host.port,
        }
    }

    #[inline(always)]
    fn credentials(&self) -> Option<&Credentials<String>> {
        match self {
            NextHop::MX(_) => None,
            NextHop::Relay(host) => host.auth.as_ref(),
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
            NextHop::MX(_) => false,
            NextHop::Relay(host) => host.tls_allow_invalid_certs,
        }
    }

    #[inline(always)]
    fn implicit_tls(&self) -> bool {
        match self {
            NextHop::MX(_) => false,
            NextHop::Relay(host) => host.tls_implicit,
        }
    }

    #[inline(always)]
    fn is_smtp(&self) -> bool {
        match self {
            NextHop::MX(_) => true,
            NextHop::Relay(host) => host.protocol == ServerProtocol::Smtp,
        }
    }
}
