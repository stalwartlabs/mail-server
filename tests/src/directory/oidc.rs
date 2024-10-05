/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::sync::Arc;

use base64::{engine::general_purpose, Engine};
use directory::{backend::internal::PrincipalField, QueryBy};
use hyper::{Method, StatusCode};
use jmap::api::{http::ToHttpResponse, JsonResponse};
use mail_send::Credentials;
use serde_json::json;
use trc::{AuthEvent, EventType};

use crate::{
    directory::DirectoryTest,
    http_server::{spawn_mock_http_server, HttpMessage},
};

static TEST_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";

#[tokio::test]
async fn oidc_directory() {
    // Obtain directory handle
    let mut config = DirectoryTest::new("rocksdb".into()).await;

    // Spawn mock OIDC server
    let _tx = spawn_mock_http_server(Arc::new(|req: HttpMessage| {
        let success_response = JsonResponse::new(json!({
            "email": "john@example.org",
            "preferred_username": "jdoe",
            "name": "John Doe",
        }))
        .into_http_response();

        match (req.method.clone(), req.uri.path().split('/').nth(1)) {
            (Method::GET, Some("userinfo")) => match req.headers.get("authorization") {
                Some(auth) if auth == &format!("Bearer {TEST_TOKEN}") => success_response,
                Some(_) => StatusCode::UNAUTHORIZED.into_http_response(),
                None => panic!("Missing Authorization header: {req:#?}"),
            },
            (Method::POST, Some("introspect-none")) => {
                assert!(req.headers.get("authorization").is_none());
                if req.get_url_encoded("token").as_deref() == Some(TEST_TOKEN) {
                    success_response
                } else {
                    StatusCode::UNAUTHORIZED.into_http_response()
                }
            }
            (Method::POST, Some("introspect-user-token")) => match req.headers.get("authorization")
            {
                Some(auth)
                    if auth == &format!("Bearer {TEST_TOKEN}")
                        && req.get_url_encoded("token").as_deref() == Some(TEST_TOKEN) =>
                {
                    success_response
                }
                Some(_) => StatusCode::UNAUTHORIZED.into_http_response(),
                None => panic!("Missing Authorization header: {req:#?}"),
            },
            (Method::POST, Some("introspect-token")) => match req.headers.get("authorization") {
                Some(auth)
                    if auth == "Bearer token_of_gratitude"
                        && req.get_url_encoded("token").as_deref() == Some(TEST_TOKEN) =>
                {
                    success_response
                }
                Some(_) => StatusCode::UNAUTHORIZED.into_http_response(),
                None => panic!("Missing Authorization header: {req:#?}"),
            },
            (Method::POST, Some("introspect-basic")) => match req.headers.get("authorization") {
                Some(auth)
                    if auth
                        == &format!(
                            "Basic {}",
                            general_purpose::STANDARD.encode("myuser:mypass".as_bytes())
                        )
                        && req.get_url_encoded("token").as_deref() == Some(TEST_TOKEN) =>
                {
                    success_response
                }
                Some(_) => StatusCode::UNAUTHORIZED.into_http_response(),
                None => panic!("Missing Authorization header: {req:#?}"),
            },
            _ => panic!("Unexpected request: {:?}", req),
        }
    }))
    .await;

    for test in [
        "oidc-userinfo",
        "oidc-introspect-none",
        "oidc-introspect-user-token",
        "oidc-introspect-token",
        "oidc-introspect-basic",
    ] {
        println!("Running OIDC test {test:?}...");
        let directory = config.directories.directories.remove(test).unwrap();

        // Test an invalid token
        let err = directory
            .query(
                QueryBy::Credentials(&Credentials::OAuthBearer {
                    token: "invalid_or_expired_token".to_string(),
                }),
                false,
            )
            .await
            .unwrap_err();
        assert!(
            err.matches(EventType::Auth(AuthEvent::Failed)),
            "Unexpected error: {:?}",
            err
        );

        // Test a valid token
        let principal = directory
            .query(
                QueryBy::Credentials(&Credentials::OAuthBearer {
                    token: TEST_TOKEN.to_string(),
                }),
                false,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(principal.name(), "jdoe");
        assert_eq!(
            principal.get_str(PrincipalField::Emails),
            Some("john@example.org")
        );
        assert_eq!(principal.description(), Some("John Doe"));
    }
}
