/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use ahash::HashMap;
use mail_send::Credentials;
use reqwest::{header::AUTHORIZATION, StatusCode};
use trc::{AddContext, AuthEvent};

use crate::{
    backend::{
        internal::{
            lookup::DirectoryStore,
            manage::{self, ManageDirectory, UpdatePrincipal},
            PrincipalField,
        },
        oidc::{Authentication, EndpointType},
    },
    Principal, QueryBy, Type, ROLE_USER,
};

use super::{OpenIdConfig, OpenIdDirectory};

type OpenIdResponse = HashMap<String, serde_json::Value>;

impl OpenIdDirectory {
    pub async fn query(
        &self,
        by: QueryBy<'_>,
        return_member_of: bool,
    ) -> trc::Result<Option<Principal>> {
        match &by {
            QueryBy::Credentials(Credentials::OAuthBearer { token }) => {
                // Send request
                #[cfg(feature = "test_mode")]
                let client = reqwest::Client::builder().danger_accept_invalid_certs(true);

                #[cfg(not(feature = "test_mode"))]
                let client = reqwest::Client::builder();

                let client = client
                    .timeout(self.config.endpoint_timeout)
                    .build()
                    .map_err(|err| {
                        AuthEvent::Error
                            .into_err()
                            .reason(err)
                            .details("Failed to build client")
                    })?;

                let client = match &self.config.endpoint_type {
                    EndpointType::UserInfo => client.get(&self.config.endpoint).bearer_auth(token),
                    EndpointType::Introspect(authentication) => {
                        let client = client.post(&self.config.endpoint).form(&[
                            ("token", token.as_str()),
                            ("token_type_hint", "access_token"),
                        ]);
                        match authentication {
                            Authentication::Header(header) => client.header(AUTHORIZATION, header),
                            Authentication::Bearer => client.bearer_auth(token),
                            Authentication::None => client,
                        }
                    }
                };

                let response = client.send().await.map_err(|err| {
                    AuthEvent::Error
                        .into_err()
                        .reason(err)
                        .details("HTTP request failed")
                })?;

                match response.status() {
                    StatusCode::OK => {
                        // Fetch response
                        let response = response.bytes().await.map_err(|err| {
                            AuthEvent::Error
                                .into_err()
                                .reason(err)
                                .details("Failed to read OIDC response")
                        })?;

                        // Deserialize response
                        let external_principal =
                            serde_json::from_slice::<OpenIdResponse>(&response)
                                .map_err(|err| {
                                    AuthEvent::Error
                                        .into_err()
                                        .reason(err)
                                        .details("Failed to deserialize OIDC response")
                                })?
                                .build_principal(&self.config)?;

                        // Fetch principal
                        let id = self
                            .data_store
                            .get_or_create_principal_id(external_principal.name(), Type::Individual)
                            .await
                            .caused_by(trc::location!())?;
                        let mut principal = self
                            .data_store
                            .query(QueryBy::Id(id), return_member_of)
                            .await
                            .caused_by(trc::location!())?
                            .ok_or_else(|| manage::not_found(id).caused_by(trc::location!()))?;

                        // Keep the internal store up to date with the OIDC server
                        let changes = principal.update_external(external_principal);
                        if !changes.is_empty() {
                            self.data_store
                                .update_principal(
                                    UpdatePrincipal::by_id(principal.id)
                                        .with_updates(changes)
                                        .create_domains(),
                                )
                                .await
                                .caused_by(trc::location!())?;
                        }

                        Ok(Some(principal))
                    }
                    StatusCode::UNAUTHORIZED => Err(trc::AuthEvent::Failed
                        .into_err()
                        .code(401)
                        .details("Unauthorized")),
                    other => Err(trc::AuthEvent::Error
                        .into_err()
                        .code(other.as_u16())
                        .ctx(trc::Key::Reason, response.text().await.unwrap_or_default())
                        .details("Unexpected status code")),
                }
            }
            _ => self.data_store.query(by, return_member_of).await,
        }
    }

    pub async fn email_to_ids(&self, address: &str) -> trc::Result<Vec<u32>> {
        self.data_store.email_to_ids(address).await
    }

    pub async fn rcpt(&self, address: &str) -> trc::Result<bool> {
        self.data_store.rcpt(address).await
    }

    pub async fn vrfy(&self, address: &str) -> trc::Result<Vec<String>> {
        self.data_store.vrfy(address).await
    }

    pub async fn expn(&self, address: &str) -> trc::Result<Vec<String>> {
        self.data_store.expn(address).await
    }

    pub async fn is_local_domain(&self, domain: &str) -> trc::Result<bool> {
        self.data_store.is_local_domain(domain).await
    }
}

trait BuildPrincipal {
    fn build_principal(&mut self, config: &OpenIdConfig) -> trc::Result<Principal>;
    fn take_required_field(&mut self, field: &str) -> trc::Result<String>;
    fn take_field(&mut self, field: &str) -> Option<String>;
}

impl BuildPrincipal for OpenIdResponse {
    fn build_principal(&mut self, config: &OpenIdConfig) -> trc::Result<Principal> {
        let email = self
            .take_required_field(&config.email_field)?
            .to_lowercase();
        let username = if let Some(username_field) = &config.username_field {
            self.take_required_field(username_field)?.to_lowercase()
        } else {
            email.clone()
        };
        if !email.contains('@') && !email.contains('.') {
            return Err(AuthEvent::Error
                .into_err()
                .details("Email field is not valid")
                .ctx(trc::Key::Key, email));
        }
        let full_name = config
            .full_name_field
            .as_ref()
            .and_then(|field| self.take_field(field));

        Ok(Principal::new(u32::MAX, Type::Individual)
            .with_field(PrincipalField::Name, username)
            .with_field(PrincipalField::Emails, email)
            .with_field(PrincipalField::Roles, ROLE_USER)
            .with_opt_field(PrincipalField::Description, full_name))
    }

    fn take_required_field(&mut self, field: &str) -> trc::Result<String> {
        match self.remove(field) {
            Some(serde_json::Value::String(value)) if !value.is_empty() => Ok(value),
            other => Err(trc::AuthEvent::Error
                .into_err()
                .details("Unexpected field type in OIDC response")
                .ctx(trc::Key::Key, field.to_string())
                .ctx(
                    trc::Key::Value,
                    serde_json::to_string(&other.unwrap_or(serde_json::Value::Null))
                        .unwrap_or_default(),
                )),
        }
    }

    fn take_field(&mut self, field: &str) -> Option<String> {
        match self.remove(field) {
            Some(serde_json::Value::String(value)) if !value.is_empty() => Some(value),
            _ => None,
        }
    }
}
