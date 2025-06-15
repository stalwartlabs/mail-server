/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::{
    Server,
    auth::oauth::registration::{ClientRegistrationRequest, ClientRegistrationResponse},
};

use directory::{
    Permission, QueryBy, Type,
    backend::internal::{
        PrincipalField, PrincipalSet, lookup::DirectoryStore, manage::ManageDirectory,
    },
};
use store::rand::{Rng, distr::Alphanumeric, rng};
use trc::{AddContext, AuthEvent};

use crate::auth::authenticate::Authenticator;
use http_proto::{request::fetch_body, *};

use super::ErrorType;

pub trait ClientRegistrationHandler: Sync + Send {
    fn handle_oauth_registration_request(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn validate_client_registration(
        &self,
        client_id: &str,
        redirect_uri: Option<&str>,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<ErrorType>>> + Send;
}
impl ClientRegistrationHandler for Server {
    async fn handle_oauth_registration_request(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        if !self.core.oauth.allow_anonymous_client_registration {
            // Authenticate request
            let (_, access_token) = self.authenticate_headers(req, &session, true).await?;

            // Validate permissions
            access_token.assert_has_permission(Permission::OauthClientRegistration)?;
        } else {
            self.is_http_anonymous_request_allowed(&session.remote_ip)
                .await?;
        }

        // Parse request
        let body = fetch_body(req, 20 * 1024, session.session_id).await;
        let request = serde_json::from_slice::<ClientRegistrationRequest>(
            body.as_deref().unwrap_or_default(),
        )
        .map_err(|err| {
            trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
        })?;

        // Generate client ID
        let client_id = rng()
            .sample_iter(Alphanumeric)
            .take(20)
            .map(|ch| char::from(ch.to_ascii_lowercase()))
            .collect::<String>();
        self.store()
            .create_principal(
                PrincipalSet::new(u32::MAX, Type::OauthClient)
                    .with_field(PrincipalField::Name, client_id.clone())
                    .with_field(PrincipalField::Urls, request.redirect_uris.clone())
                    .with_opt_field(PrincipalField::Description, request.client_name.clone())
                    .with_field(PrincipalField::Emails, request.contacts.clone())
                    .with_opt_field(PrincipalField::Picture, request.logo_uri.clone()),
                None,
                None,
            )
            .await
            .caused_by(trc::location!())?;

        trc::event!(
            Auth(AuthEvent::ClientRegistration),
            Id = client_id.to_string(),
            RemoteIp = session.remote_ip
        );

        Ok(JsonResponse::new(ClientRegistrationResponse {
            client_id,
            request,
            ..Default::default()
        })
        .no_cache()
        .into_http_response())
    }

    async fn validate_client_registration(
        &self,
        client_id: &str,
        redirect_uri: Option<&str>,
        account_id: u32,
    ) -> trc::Result<Option<ErrorType>> {
        if !self.core.oauth.require_client_authentication {
            return Ok(None);
        }

        // Fetch client registration
        let found_registration = if let Some(client) = self
            .store()
            .query(QueryBy::Name(client_id), false)
            .await
            .caused_by(trc::location!())?
            .filter(|p| p.typ() == Type::OauthClient)
        {
            if let Some(redirect_uri) = redirect_uri {
                if client.urls().iter().any(|uri| uri == redirect_uri) {
                    return Ok(None);
                }
            } else {
                // Device flow does not require a redirect URI

                return Ok(None);
            }

            true
        } else {
            false
        };

        // Check if the account is allowed to override client registration
        if self
            .get_access_token(account_id)
            .await
            .caused_by(trc::location!())?
            .has_permission(Permission::OauthClientOverride)
        {
            return Ok(None);
        }

        Ok(Some(if found_registration {
            ErrorType::InvalidClient
        } else {
            ErrorType::InvalidRequest
        }))
    }
}
