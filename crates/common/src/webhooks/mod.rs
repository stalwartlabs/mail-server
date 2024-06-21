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

use std::{net::IpAddr, sync::Arc, time::Duration};

use ahash::{AHashMap, AHashSet};
use chrono::{DateTime, Utc};
use hyper::HeaderMap;
use mail_auth::report::{
    tlsrpt::{PolicyType, ResultType},
    AuthFailureType, DeliveryResult, FeedbackType, IdentityAlignment,
};
use serde::{Deserialize, Serialize};

use crate::config::server::ServerProtocol;

pub mod collector;
pub mod manager;

#[derive(Clone, Default)]
pub struct Webhooks {
    pub events: AHashSet<WebhookType>,
    pub hooks: AHashMap<u64, Arc<Webhook>>,
}

#[derive(Clone)]
pub struct Webhook {
    pub id: u64,
    pub url: String,
    pub key: String,
    pub timeout: Duration,
    pub throttle: Duration,
    pub tls_allow_invalid_certs: bool,
    pub headers: HeaderMap,
    pub events: AHashSet<WebhookType>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct WebhookEvents {
    pub events: Vec<WebhookEvent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub id: u64,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "type")]
    pub typ: WebhookType,
    pub data: Arc<WebhookPayload>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebhookType {
    #[serde(rename = "auth.success")]
    AuthSuccess,
    #[serde(rename = "auth.failure")]
    AuthFailure,
    #[serde(rename = "auth.banned")]
    AuthBanned,
    #[serde(rename = "auth.error")]
    AuthError,
    #[serde(rename = "message.accepted")]
    MessageAccepted,
    #[serde(rename = "message.rejected")]
    MessageRejected,
    #[serde(rename = "message.appended")]
    MessageAppended,
    #[serde(rename = "account.over-quota")]
    AccountOverQuota,
    #[serde(rename = "dsn")]
    DSN,
    #[serde(rename = "double-bounce")]
    DoubleBounce,
    #[serde(rename = "report.incoming.dmarc")]
    IncomingDmarcReport,
    #[serde(rename = "report.incoming.tls")]
    IncomingTlsReport,
    #[serde(rename = "report.incoming.arf")]
    IncomingArfReport,
    #[serde(rename = "report.outgoing")]
    OutgoingReport,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WebhookPayload {
    Authentication {
        login: String,
        protocol: ServerProtocol,
        #[serde(rename = "remoteIp")]
        remote_ip: IpAddr,
        #[serde(rename = "accountType")]
        #[serde(skip_serializing_if = "Option::is_none")]
        typ: Option<directory::Type>,
        #[serde(rename = "isMasterLogin")]
        #[serde(skip_serializing_if = "Option::is_none")]
        as_master: Option<bool>,
    },
    Error {
        message: String,
    },
    MessageAccepted {
        #[serde(rename = "queueId")]
        id: u64,
        #[serde(rename = "remoteIp")]
        #[serde(skip_serializing_if = "Option::is_none")]
        remote_ip: Option<IpAddr>,
        #[serde(rename = "localPort")]
        #[serde(skip_serializing_if = "Option::is_none")]
        local_port: Option<u16>,
        #[serde(rename = "authenticatedAs")]
        #[serde(skip_serializing_if = "Option::is_none")]
        authenticated_as: Option<String>,
        #[serde(rename = "returnPath")]
        return_path: String,
        recipients: Vec<String>,
        #[serde(rename = "nextRetry")]
        next_retry: DateTime<Utc>,
        #[serde(rename = "nextDSN")]
        next_dsn: DateTime<Utc>,
        expires: DateTime<Utc>,
        size: usize,
    },
    MessageRejected {
        reason: WebhookMessageFailure,
        #[serde(rename = "remoteIp")]
        remote_ip: IpAddr,
        #[serde(rename = "localPort")]
        local_port: u16,
        #[serde(rename = "authenticatedAs")]
        #[serde(skip_serializing_if = "Option::is_none")]
        authenticated_as: Option<String>,
        #[serde(rename = "returnPath")]
        #[serde(skip_serializing_if = "Option::is_none")]
        return_path: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        recipients: Vec<String>,
    },
    MessageAppended {
        #[serde(rename = "accountId")]
        account_id: u32,
        #[serde(rename = "mailboxIds")]
        mailbox_ids: Vec<u32>,
        source: WebhookIngestSource,
        encrypt: bool,
        size: usize,
    },
    DSN {
        #[serde(rename = "queueId")]
        id: u64,
        sender: String,
        status: Vec<WebhookDSN>,
        #[serde(rename = "createdAt")]
        created: DateTime<Utc>,
    },
    IncomingDmarcReport {
        #[serde(rename = "rangeFrom")]
        range_from: String,
        #[serde(rename = "rangeTo")]
        range_to: String,
        domain: String,
        #[serde(rename = "reportEmail")]
        report_email: String,
        #[serde(rename = "reportId")]
        report_id: String,
        #[serde(rename = "dmarcPass")]
        dmarc_pass: u32,
        #[serde(rename = "dmarcQuarantine")]
        dmarc_quarantine: u32,
        #[serde(rename = "dmarcReject")]
        dmarc_reject: u32,
        #[serde(rename = "dmarcNone")]
        dmarc_none: u32,
        #[serde(rename = "dkimPass")]
        dkim_pass: u32,
        #[serde(rename = "dkimFail")]
        dkim_fail: u32,
        #[serde(rename = "dkimNone")]
        dkim_none: u32,
        #[serde(rename = "spfPass")]
        spf_pass: u32,
        #[serde(rename = "spfFail")]
        spf_fail: u32,
        #[serde(rename = "spfNone")]
        spf_none: u32,
    },
    IncomingTlsReport {
        policies: Vec<WebhookTlsPolicy>,
    },
    IncomingArfReport {
        #[serde(rename = "feedbackType")]
        feedback_type: FeedbackType,
        #[serde(rename = "arrivalDate")]
        #[serde(skip_serializing_if = "Option::is_none")]
        arrival_date: Option<String>,
        #[serde(rename = "authenticationResults")]
        #[serde(skip_serializing_if = "Vec::is_empty")]
        authentication_results: Vec<String>,
        incidents: u32,
        #[serde(rename = "reportedDomains")]
        #[serde(skip_serializing_if = "Vec::is_empty")]
        reported_domain: Vec<String>,
        #[serde(rename = "reportedUris")]
        #[serde(skip_serializing_if = "Vec::is_empty")]
        reported_uri: Vec<String>,
        #[serde(rename = "reportingMTA")]
        #[serde(skip_serializing_if = "Option::is_none")]
        reporting_mta: Option<String>,
        #[serde(rename = "sourceIp")]
        #[serde(skip_serializing_if = "Option::is_none")]
        source_ip: Option<IpAddr>,
        #[serde(rename = "userAgent")]
        #[serde(skip_serializing_if = "Option::is_none")]
        user_agent: Option<String>,
        #[serde(rename = "authFailureType")]
        #[serde(skip_serializing_if = "has_no_auth_failure")]
        auth_failure: AuthFailureType,
        #[serde(rename = "deliveryResult")]
        #[serde(skip_serializing_if = "has_no_delivery_result")]
        delivery_result: DeliveryResult,
        #[serde(rename = "dkimDomain")]
        #[serde(skip_serializing_if = "Option::is_none")]
        dkim_domain: Option<String>,
        #[serde(rename = "dkimIdentity")]
        #[serde(skip_serializing_if = "Option::is_none")]
        dkim_identity: Option<String>,
        #[serde(rename = "dkimSelector")]
        #[serde(skip_serializing_if = "Option::is_none")]
        dkim_selector: Option<String>,
        #[serde(rename = "identityAlignment")]
        #[serde(skip_serializing_if = "has_no_alignment")]
        identity_alignment: IdentityAlignment,
    },
    AccountOverQuota {
        #[serde(rename = "accountId")]
        account_id: u32,
        #[serde(rename = "quotaLimit")]
        quota_limit: usize,
        #[serde(rename = "quotaUsed")]
        quota_used: usize,
        #[serde(rename = "objectSize")]
        object_size: usize,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookTlsPolicy {
    #[serde(rename = "rangeFrom")]
    pub range_from: String,
    #[serde(rename = "rangeTo")]
    pub range_to: String,
    pub domain: String,
    #[serde(rename = "reportContact")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_contact: Option<String>,
    #[serde(rename = "reportId")]
    pub report_id: String,
    #[serde(rename = "policyType")]
    pub policy_type: PolicyType,
    #[serde(rename = "totalSuccesses")]
    pub total_successes: u32,
    #[serde(rename = "totalFailures")]
    pub total_failures: u32,
    pub details: AHashMap<ResultType, u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookDSN {
    pub address: String,
    #[serde(rename = "remoteHost")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_host: Option<String>,
    #[serde(rename = "type")]
    pub typ: WebhookDSNType,
    pub message: String,
    #[serde(rename = "nextRetry")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "retryCount")]
    pub retry_count: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WebhookDSNType {
    Success,
    TemporaryFailure,
    PermanentFailure,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum WebhookMessageFailure {
    ParseFailed,
    LoopDetected,
    DkimPolicy,
    ArcPolicy,
    DmarcPolicy,
    MilterReject,
    SieveDiscard,
    SieveReject,
    QuotaExceeded,
    ServerFailure,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum WebhookIngestSource {
    Smtp,
    Jmap,
    Imap,
}

fn has_no_alignment(alignment: &IdentityAlignment) -> bool {
    matches!(
        alignment,
        IdentityAlignment::None | IdentityAlignment::Unspecified
    )
}

fn has_no_delivery_result(result: &DeliveryResult) -> bool {
    matches!(result, DeliveryResult::Unspecified)
}

fn has_no_auth_failure(failure: &AuthFailureType) -> bool {
    matches!(failure, AuthFailureType::Unspecified)
}
