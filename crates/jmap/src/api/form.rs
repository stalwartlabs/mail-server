/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Write, future::Future};

use chrono::Utc;
use common::{
    config::network::{ContactForm, FieldOrDefault},
    ipc::{DeliveryResult, IngestMessage},
    psl, Server,
};
use hyper::StatusCode;
use mail_builder::{
    headers::{
        address::{Address, EmailAddress},
        HeaderType,
    },
    mime::make_boundary,
    MessageBuilder,
};
use serde_json::json;
use store::{
    write::{now, BatchBuilder, BlobOp},
    Serialize,
};
use trc::AddContext;
use utils::BlobHash;
use x509_parser::nom::AsBytes;

use crate::{auth::oauth::FormData, services::ingest::MailDelivery};

use super::{
    http::{HttpSessionData, ToHttpResponse},
    HttpResponse, JsonResponse,
};

pub trait FormHandler: Sync + Send {
    fn handle_contact_form(
        &self,
        session: &HttpSessionData,
        form: &ContactForm,
        form_data: FormData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl FormHandler for Server {
    async fn handle_contact_form(
        &self,
        session: &HttpSessionData,
        form: &ContactForm,
        form_data: FormData,
    ) -> trc::Result<HttpResponse> {
        // Validate rate
        if let Some(rate) = &form.rate {
            if !session.remote_ip.is_loopback()
                && self
                    .core
                    .storage
                    .lookup
                    .is_rate_allowed(
                        format!("contact:{}", session.remote_ip).as_bytes(),
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

        // Validate honeypot
        if form
            .field_honey_pot
            .as_ref()
            .map_or(false, |field| form_data.has_field(field))
        {
            return Err(trc::ResourceEvent::BadParameters
                .into_err()
                .details("Honey pot field present"));
        }

        // Obtain fields
        let from_email = form_data
            .get_or_default(&form.from_email)
            .trim()
            .to_lowercase();
        let from_subject = form_data.get_or_default(&form.from_subject).trim();
        let from_name = form_data.get_or_default(&form.from_name).trim();

        // Validate email
        let mut failure = None;
        let mut has_success = false;
        if form.validate_domain && from_email != form.from_email.default {
            if let Some(domain) = from_email.rsplit_once('@').and_then(|(local, domain)| {
                if !local.is_empty()
                    && domain.contains('.')
                    && psl::suffix(domain.as_bytes()).is_some()
                {
                    Some(domain)
                } else {
                    None
                }
            }) {
                if self
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .mx_lookup(domain)
                    .await
                    .is_err()
                {
                    failure = Some(format!("No MX records found for domain {domain:?}. Please enter a valid email address.", ).into());
                }
            } else {
                failure = Some(Cow::Borrowed("Please enter a valid email address."));
            }
        }

        if failure.is_none() {
            // Build body
            let mut body = String::with_capacity(1024);
            for (field, value) in form_data.fields() {
                if !value.is_empty() {
                    body.push_str(field);
                    body.push_str(": ");
                    body.push_str(value);
                    body.push_str("\r\n");
                }
            }
            let _ = write!(
                &mut body,
                "Date: {}\r\n",
                Utc::now().format("%a, %d %b %Y %T %z")
            );
            let _ = write!(
                &mut body,
                "IP: {}:{}\r\n",
                session.remote_ip, session.remote_port
            );

            // Build message
            let message = MessageBuilder::new()
                .from((from_name, from_email.as_str()))
                .header(
                    "To",
                    HeaderType::Address(Address::List(
                        form.rcpt_to
                            .iter()
                            .map(|rcpt| {
                                Address::Address(EmailAddress {
                                    name: None,
                                    email: rcpt.into(),
                                })
                            })
                            .collect(),
                    )),
                )
                .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
                .message_id(format!(
                    "<{}@{}.{}>",
                    make_boundary("."),
                    session.remote_ip,
                    session.remote_port
                ))
                .subject(from_subject)
                .text_body(body)
                .write_to_vec()
                .unwrap_or_default();

            // Reserve and write blob
            let message_blob = BlobHash::from(message.as_bytes());
            let message_size = message.len();
            let mut batch = BatchBuilder::new();
            batch.set(
                BlobOp::Reserve {
                    hash: message_blob.clone(),
                    until: now() + 120,
                },
                0u32.serialize(),
            );
            self.store()
                .write(batch.build())
                .await
                .caused_by(trc::location!())?;
            self.blob_store()
                .put_blob(message_blob.as_slice(), message.as_ref())
                .await
                .caused_by(trc::location!())?;

            for result in self
                .deliver_message(IngestMessage {
                    sender_address: from_email,
                    recipients: form.rcpt_to.clone(),
                    message_blob,
                    message_size,
                    session_id: session.session_id,
                })
                .await
            {
                match result {
                    DeliveryResult::Success => {
                        has_success = true;
                    }
                    DeliveryResult::TemporaryFailure { reason }
                    | DeliveryResult::PermanentFailure { reason, .. } => failure = Some(reason),
                }
            }

            // Suppress errors if there is at least one success
            if has_success {
                failure = None;
            }
        }

        Ok(JsonResponse::with_status(
            if has_success {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            },
            json!({
                "data": {
                    "success": has_success,
                    "details": failure,
                },
            }),
        )
        .into_http_response())
    }
}

impl FormData {
    pub fn get_or_default<'x>(&'x self, field: &'x FieldOrDefault) -> &'x str {
        if let Some(field_name) = &field.field {
            self.get(field_name)
                .filter(|f| !f.is_empty())
                .unwrap_or(field.default.as_str())
        } else {
            field.default.as_str()
        }
    }
}
