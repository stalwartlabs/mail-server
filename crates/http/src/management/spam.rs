/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use common::{Server, auth::AccessToken, config::spamfilter::SpamFilterAction, psl};

use compact_str::CompactString;
use directory::{
    Permission,
    backend::internal::manage::{self, ManageDirectory},
};
use hyper::Method;
use mail_auth::{
    AuthenticatedMessage, DmarcResult, dmarc::verify::DmarcParameters, spf::verify::SpfParameters,
};
use mail_parser::{Message, MessageParser};
use serde::{Deserialize, Serialize};
use serde_json::json;
use spam_filter::{
    SpamFilterInput,
    analysis::{init::SpamFilterInit, score::SpamFilterAnalyzeScore},
    modules::bayes::BayesClassifier,
};
use std::future::Future;
use store::ahash::AHashMap;

use http_proto::{request::decode_path_element, *};

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

    // Session details
    pub remote_ip: IpAddr,
    #[serde(default)]
    pub ehlo_domain: String,
    #[serde(default)]
    pub authenticated_as: Option<String>,

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
    pub tags: AHashMap<CompactString, SpamFilterDisposition<f64>>,
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
                let input = if let Some(account) = path.get(3).copied().filter(|a| !a.is_empty()) {
                    let account_id = self
                        .store()
                        .get_principal_id(decode_path_element(account).as_ref())
                        .await?
                        .ok_or_else(|| manage::not_found(account.to_string()))?;
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

                // Built spam filter input
                let message = parse_message_or_err(request.message.as_bytes())?;

                let remote_ip = request.remote_ip;
                let ehlo_domain = request.ehlo_domain.to_lowercase();
                let mail_from = request.env_from.to_lowercase();
                let mail_from_domain = mail_from.rsplit_once('@').map(|(_, domain)| domain);
                let local_host = &self.core.network.server_name;

                let spf_ehlo_result =
                    self.core
                        .smtp
                        .resolvers
                        .dns
                        .verify_spf(self.inner.cache.build_auth_parameters(
                            SpfParameters::verify_ehlo(remote_ip, &ehlo_domain, local_host),
                        ))
                        .await;

                let iprev_result = self
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .verify_iprev(self.inner.cache.build_auth_parameters(remote_ip))
                    .await;

                let spf_mail_from_result = if let Some(mail_from_domain) = mail_from_domain {
                    self.core
                        .smtp
                        .resolvers
                        .dns
                        .check_host(self.inner.cache.build_auth_parameters(SpfParameters::new(
                            remote_ip,
                            mail_from_domain,
                            &ehlo_domain,
                            local_host,
                            &mail_from,
                        )))
                        .await
                } else {
                    self.core
                        .smtp
                        .resolvers
                        .dns
                        .check_host(self.inner.cache.build_auth_parameters(SpfParameters::new(
                            remote_ip,
                            &ehlo_domain,
                            &ehlo_domain,
                            local_host,
                            &format!("postmaster@{ehlo_domain}"),
                        )))
                        .await
                };

                let auth_message = AuthenticatedMessage::from_parsed(&message, true);

                let dkim_output = self
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .verify_dkim(self.inner.cache.build_auth_parameters(&auth_message))
                    .await;

                let arc_output = self
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .verify_arc(self.inner.cache.build_auth_parameters(&auth_message))
                    .await;

                let dmarc_output = self
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .verify_dmarc(self.inner.cache.build_auth_parameters(DmarcParameters {
                        message: &auth_message,
                        dkim_output: &dkim_output,
                        rfc5321_mail_from_domain: mail_from_domain.unwrap_or(ehlo_domain.as_str()),
                        spf_output: &spf_mail_from_result,
                        domain_suffix_fn: |domain| psl::domain_str(domain).unwrap_or(domain),
                    }))
                    .await;
                let dmarc_pass = matches!(dmarc_output.spf_result(), DmarcResult::Pass)
                    || matches!(dmarc_output.dkim_result(), DmarcResult::Pass);
                let dmarc_result = if dmarc_pass {
                    DmarcResult::Pass
                } else if dmarc_output.spf_result() != &DmarcResult::None {
                    dmarc_output.spf_result().clone()
                } else if dmarc_output.dkim_result() != &DmarcResult::None {
                    dmarc_output.dkim_result().clone()
                } else {
                    DmarcResult::None
                };
                let dmarc_policy = dmarc_output.policy();

                let asn_geo = self.lookup_asn_country(remote_ip).await;

                let input = SpamFilterInput {
                    message: &message,
                    span_id: session.session_id,
                    arc_result: Some(&arc_output),
                    spf_ehlo_result: Some(&spf_ehlo_result),
                    spf_mail_from_result: Some(&spf_mail_from_result),
                    dkim_result: dkim_output.as_slice(),
                    dmarc_result: Some(&dmarc_result),
                    dmarc_policy: Some(&dmarc_policy),
                    iprev_result: Some(&iprev_result),
                    remote_ip: request.remote_ip,
                    ehlo_domain: Some(ehlo_domain.as_str()),
                    authenticated_as: request.authenticated_as.as_deref(),
                    asn: asn_geo.asn.as_ref().map(|a| a.id),
                    country: asn_geo.country.as_ref().map(|c| c.as_str()),
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
