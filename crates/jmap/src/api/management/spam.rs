/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::IpAddr, sync::Arc};

use common::{
    auth::AccessToken, config::spamfilter::SpamFilterAction, scripts::ScriptModification, Server,
};
use directory::{
    backend::internal::manage::{self, ManageDirectory},
    Permission,
};
use hyper::Method;
use mail_auth::{ArcOutput, DkimOutput, IprevOutput};
use mail_parser::{Message, MessageParser};
use serde::{Deserialize, Serialize};
use serde_json::json;
use spam_filter::{
    analysis::{init::SpamFilterInit, score::SpamFilterAnalyzeScore},
    modules::bayes::BayesClassifier,
    SpamFilterInput,
};
use std::future::Future;
use store::ahash::AHashMap;

use crate::api::{
    http::{HttpSessionData, ToHttpResponse},
    HttpRequest, HttpResponse, JsonResponse,
};

use super::{
    decode_path_element,
    troubleshoot::{AuthResult, DmarcPolicy},
};

#[derive(Debug, serde::Serialize)]
#[serde(tag = "action")]
#[serde(rename_all = "lowercase")]
pub enum Response {
    Accept {
        modifications: Vec<ScriptModification>,
    },
    Replace {
        message: String,
        modifications: Vec<ScriptModification>,
    },
    Reject {
        reason: String,
    },
    Discard,
}

pub trait ManageSpamHandler: Sync + Send {
    fn handle_manage_spam(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        session: &HttpSessionData,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpamClassifyRequest {
    pub message: String,

    // Sender authentication
    pub arc_result: AuthResult,
    pub spf_ehlo_result: AuthResult,
    pub spf_mail_from_result: AuthResult,
    pub dkim_result: AuthResult,
    pub dmarc_result: AuthResult,
    pub dmarc_policy: DmarcPolicy,
    pub iprev_result: AuthResult,

    // Session details
    pub remote_ip: IpAddr,
    #[serde(default)]
    pub remote_ip_ptr: Option<String>,
    #[serde(default)]
    pub ehlo_domain: Option<String>,
    #[serde(default)]
    pub authenticated_as: Option<String>,
    #[serde(default)]
    pub asn: Option<u32>,
    #[serde(default)]
    pub country: Option<String>,

    // TLS
    #[serde(default)]
    pub is_tls: bool,

    // Envelope
    pub env_from: String,
    pub env_from_flags: u64,
    pub env_rcpt_to: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpamClassifyResponse {
    pub score: f64,
    pub tags: AHashMap<String, SpamFilterDisposition<f64>>,
    pub disposition: SpamFilterDisposition<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "action")]
pub enum SpamFilterDisposition<T> {
    Allow { value: T },
    Discard,
    Reject,
}

impl ManageSpamHandler for Server {
    async fn handle_manage_spam(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        session: &HttpSessionData,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        // Validate the access token
        access_token.assert_has_permission(Permission::SpamFilterTrain)?;

        match (path.get(1).copied(), path.get(2).copied(), req.method()) {
            (Some("train"), Some(class @ ("ham" | "spam")), &Method::POST) => {
                let message = parse_message_or_err(body.as_deref().unwrap_or_default())?;
                let input = if let Some(account) = path.get(3).copied() {
                    let account_id = self
                        .store()
                        .get_principal_id(decode_path_element(account).as_ref())
                        .await?
                        .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;
                    SpamFilterInput::from_account_message(&message, account_id, session.session_id)
                } else {
                    SpamFilterInput::from_message(&message, session.session_id)
                };
                self.bayes_train(&self.spam_filter_init(input), class == "spam", true)
                    .await?;

                Ok(JsonResponse::new(json!({
                    "data": (),
                }))
                .into_http_response())
            }
            (Some("classify"), _, &Method::POST) => {
                // Parse request
                let request = serde_json::from_slice::<SpamClassifyRequest>(
                    body.as_deref().unwrap_or_default(),
                )
                .map_err(|err| {
                    trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
                })?;

                // Built classifier input
                let message = parse_message_or_err(request.message.as_bytes())?;
                let arc_result = ArcOutput::default().with_result(request.arc_result.into());
                let spf_ehlo_result = request.spf_ehlo_result.into();
                let spf_mail_from_result = request.spf_mail_from_result.into();
                let dkim_result = vec![match request.dkim_result {
                    AuthResult::Pass => DkimOutput::pass(),
                    AuthResult::Fail { details } => {
                        DkimOutput::fail(mail_auth::Error::Io(details.unwrap_or_default()))
                    }
                    AuthResult::Neutral { details } => {
                        DkimOutput::neutral(mail_auth::Error::Io(details.unwrap_or_default()))
                    }
                    AuthResult::TempError { details } => {
                        DkimOutput::temp_err(mail_auth::Error::Io(details.unwrap_or_default()))
                    }
                    AuthResult::PermError { details } => {
                        DkimOutput::perm_err(mail_auth::Error::Io(details.unwrap_or_default()))
                    }
                    _ => DkimOutput::neutral(mail_auth::Error::ParseError),
                }];
                let dmarc_result = request.dmarc_result.into();
                let dmarc_policy = request.dmarc_policy.into();
                let iprev_result = IprevOutput {
                    result: request.iprev_result.into(),
                    ptr: request.remote_ip_ptr.map(|ptr| Arc::new(vec![ptr])),
                };
                let input = SpamFilterInput {
                    message: &message,
                    span_id: session.session_id,
                    arc_result: Some(&arc_result),
                    spf_ehlo_result: Some(&spf_ehlo_result),
                    spf_mail_from_result: Some(&spf_mail_from_result),
                    dkim_result: dkim_result.as_slice(),
                    dmarc_result: Some(&dmarc_result),
                    dmarc_policy: Some(&dmarc_policy),
                    iprev_result: Some(&iprev_result),
                    remote_ip: request.remote_ip,
                    ehlo_domain: request.ehlo_domain.as_deref(),
                    authenticated_as: request.authenticated_as.as_deref(),
                    asn: request.asn,
                    country: request.country.as_deref(),
                    is_tls: request.is_tls,
                    env_from: &request.env_from,
                    env_from_flags: request.env_from_flags,
                    env_rcpt_to: request.env_rcpt_to.iter().map(String::as_str).collect(),
                    account_id: None,
                    is_test: true,
                };

                // Classify
                let mut ctx = self.spam_filter_init(input);
                let result = self.spam_filter_classify(&mut ctx).await;

                // Build response
                let mut response = SpamClassifyResponse {
                    score: ctx.result.score,
                    tags: AHashMap::with_capacity(ctx.result.tags.len()),
                    disposition: match result {
                        SpamFilterAction::Allow(value) => SpamFilterDisposition::Allow { value },
                        SpamFilterAction::Discard => SpamFilterDisposition::Discard,
                        SpamFilterAction::Reject => SpamFilterDisposition::Reject,
                    },
                };
                for tag in ctx.result.tags {
                    let disposition = match self.core.spam.lists.scores.get(&tag) {
                        Some(SpamFilterAction::Allow(score)) => {
                            SpamFilterDisposition::Allow { value: *score }
                        }
                        Some(SpamFilterAction::Discard) => SpamFilterDisposition::Discard,
                        Some(SpamFilterAction::Reject) => SpamFilterDisposition::Reject,
                        None => SpamFilterDisposition::Allow { value: 0.0 },
                    };
                    response.tags.insert(tag, disposition);
                }

                Ok(JsonResponse::new(json!({
                    "data": response,
                }))
                .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}

fn parse_message_or_err(bytes: &[u8]) -> trc::Result<Message<'_>> {
    MessageParser::new()
        .parse(bytes)
        .filter(|m| m.root_part().headers().iter().any(|h| !h.name.is_other()))
        .ok_or_else(|| manage::error("Failed to parse message.", None::<u64>))
}
