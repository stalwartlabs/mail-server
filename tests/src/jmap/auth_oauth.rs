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

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use jmap::{
    auth::oauth::{DeviceAuthResponse, ErrorType, OAuthMetadata, TokenResponse},
    JMAP,
};
use jmap_client::{
    client::{Client, Credentials},
    mailbox::query::Filter,
};
use jmap_proto::types::id::Id;
use reqwest::{header, redirect::Policy};
use serde::de::DeserializeOwned;
use store::ahash::AHashMap;

use crate::{
    directory::sql::create_test_user_with_email,
    jmap::{assert_is_empty, mailbox::destroy_all_mailboxes},
};

pub async fn test(server: Arc<JMAP>, admin_client: &mut Client) {
    println!("Running OAuth tests...");

    // Create test account
    let directory = server.directory.as_ref();
    create_test_user_with_email(directory, "jdoe@example.com", "12345", "John Doe").await;
    let john_id = Id::from(server.get_account_id("jdoe@example.com").await.unwrap()).to_string();

    // Obtain OAuth metadata
    let metadata: OAuthMetadata =
        get("https://127.0.0.1:8899/.well-known/oauth-authorization-server").await;
    //println!("OAuth metadata: {:#?}", metadata);

    // ------------------------
    // Authorization code flow
    // ------------------------

    // Build authorization request
    let auth_endpoint = format!(
        "{}?response_type=token&client_id=OAuthyMcOAuthFace&state=xyz&redirect_uri=https://localhost",
        metadata.authorization_endpoint
    );
    let mut auth_request = AHashMap::from_iter([
        ("email".to_string(), "jdoe@example.com".to_string()),
        ("password".to_string(), "wrong_pass".to_string()),
        (
            "code".to_string(),
            parse_code_input(get_bytes(&auth_endpoint).await),
        ),
    ]);

    // Exceeding the max failed attempts should redirect with an access_denied code
    assert_eq!(
        post_expect_redirect(&metadata.authorization_endpoint, &auth_request).await,
        "https://localhost?error=access_denied&state=xyz"
    );

    // Authenticate with the correct password
    auth_request.insert("password".to_string(), "12345".to_string());
    auth_request.insert(
        "code".to_string(),
        parse_code_input(get_bytes(&auth_endpoint).await),
    );
    let code = parse_code_redirect(
        post_expect_redirect(&metadata.authorization_endpoint, &auth_request).await,
        "xyz",
    );

    // Both client_id and redirect_uri have to match
    let mut token_params = AHashMap::from_iter([
        ("client_id".to_string(), "invalid_client".to_string()),
        ("redirect_uri".to_string(), "https://localhost".to_string()),
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), code),
    ]);
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::InvalidClient
        }
    );
    token_params.insert("client_id".to_string(), "OAuthyMcOAuthFace".to_string());
    token_params.insert(
        "redirect_uri".to_string(),
        "https://some-other.url".to_string(),
    );
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::InvalidClient
        }
    );

    // Obtain token
    token_params.insert("redirect_uri".to_string(), "https://localhost".to_string());
    let (token, _, _) = unwrap_token_response(post(&metadata.token_endpoint, &token_params).await);

    // Connect to account using token and attempt to search
    let john_client = Client::new()
        .credentials(Credentials::bearer(&token))
        .accept_invalid_certs(true)
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    assert_eq!(john_client.default_account_id(), john_id);
    assert!(!john_client
        .mailbox_query(None::<Filter>, None::<Vec<_>>)
        .await
        .unwrap()
        .ids()
        .is_empty());

    // ------------------------
    // Device code flow
    // ------------------------

    // Request a device code
    let device_code_params = AHashMap::from_iter([("client_id".to_string(), "1234".to_string())]);
    let device_response: DeviceAuthResponse =
        post(&metadata.device_authorization_endpoint, &device_code_params).await;
    //println!("Device response: {:#?}", device_response);

    // Status should be pending
    let mut token_params = AHashMap::from_iter([
        ("client_id".to_string(), "1234".to_string()),
        (
            "grant_type".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ),
        (
            "device_code".to_string(),
            device_response.device_code.to_string(),
        ),
    ]);
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::AuthorizationPending
        }
    );

    // Invalidate the code by having too many unsuccessful attempts
    assert_client_auth(
        "jdoe@example.com",
        "wrongpass",
        &device_response,
        "Incorrect",
    )
    .await;
    assert_client_auth(
        "jdoe@example.com",
        "wrongpass",
        &device_response,
        "Invalid or expired authentication code.",
    )
    .await;
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::AccessDenied
        }
    );

    // Request a new device code
    let device_response: DeviceAuthResponse =
        post(&metadata.device_authorization_endpoint, &device_code_params).await;
    token_params.insert(
        "device_code".to_string(),
        device_response.device_code.to_string(),
    );

    // Let the code expire and make sure it's invalidated
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_client_auth(
        "jdoe@example.com",
        "12345",
        &device_response,
        "Invalid or expired authentication code.",
    )
    .await;
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::ExpiredToken
        }
    );

    // Authenticate account using a valid code
    let device_response: DeviceAuthResponse =
        post(&metadata.device_authorization_endpoint, &device_code_params).await;
    token_params.insert(
        "device_code".to_string(),
        device_response.device_code.to_string(),
    );
    assert_client_auth("jdoe@example.com", "12345", &device_response, "successful").await;

    // Obtain token
    let time_first_token = Instant::now();
    let (token, refresh_token, _) =
        unwrap_token_response(post(&metadata.token_endpoint, &token_params).await);
    let refresh_token = refresh_token.unwrap();

    // Authorization codes can only be used once
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::ExpiredToken
        }
    );

    // Connect to account using token and attempt to search
    let john_client = Client::new()
        .credentials(Credentials::bearer(&token))
        .accept_invalid_certs(true)
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    assert_eq!(john_client.default_account_id(), john_id);
    assert!(!john_client
        .mailbox_query(None::<Filter>, None::<Vec<_>>)
        .await
        .unwrap()
        .ids()
        .is_empty());

    // Connecting using the refresh token should not work
    assert_unauthorized("https://127.0.0.1:8899", &refresh_token).await;

    // Refreshing a token using the access token should not work
    assert_eq!(
        post::<TokenResponse>(
            &metadata.token_endpoint,
            &AHashMap::from_iter([
                ("client_id".to_string(), "1234".to_string()),
                ("grant_type".to_string(), "refresh_token".to_string()),
                ("refresh_token".to_string(), token),
            ]),
        )
        .await,
        TokenResponse::Error {
            error: ErrorType::InvalidGrant
        }
    );

    // Refreshing the access token before expiration should not include a new refresh token
    let refresh_params = AHashMap::from_iter([
        ("client_id".to_string(), "1234".to_string()),
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("refresh_token".to_string(), refresh_token),
    ]);
    let time_before_post: Instant = Instant::now();
    let (token, new_refresh_token, _) =
        unwrap_token_response(post(&metadata.token_endpoint, &refresh_params).await);
    assert_eq!(
        new_refresh_token,
        None,
        "Refreshed token in {:?}, since start {:?}",
        time_before_post.elapsed(),
        time_first_token.elapsed()
    );

    // Wait 1 second and make sure the access token expired
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_unauthorized("https://127.0.0.1:8899", &token).await;

    // Wait another second for the refresh token to be about to expire
    // and expect a new refresh token
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (_, new_refresh_token, _) =
        unwrap_token_response(post(&metadata.token_endpoint, &refresh_params).await);
    //println!("New refresh token: {:?}", new_refresh_token);
    assert_ne!(new_refresh_token, None);

    // Wait another second and make sure the refresh token expired
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &refresh_params).await,
        TokenResponse::Error {
            error: ErrorType::InvalidGrant
        }
    );

    // Destroy test accounts
    admin_client.set_default_account_id(john_id);
    destroy_all_mailboxes(admin_client).await;
    assert_is_empty(server).await;
}

async fn post_bytes(url: &str, params: &AHashMap<String, String>) -> Bytes {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .post(url)
        .form(params)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
}

async fn post<T: DeserializeOwned>(url: &str, params: &AHashMap<String, String>) -> T {
    serde_json::from_slice(&post_bytes(url, params).await).unwrap()
}

async fn post_expect_redirect(url: &str, params: &AHashMap<String, String>) -> String {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .redirect(Policy::none())
        .build()
        .unwrap_or_default()
        .post(url)
        .form(params)
        .send()
        .await
        .unwrap();
    response
        .headers()
        .get(header::LOCATION)
        .expect("no Location header found in response")
        .to_str()
        .unwrap()
        .to_string()
}

async fn get_bytes(url: &str) -> Bytes {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .get(url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
}

async fn get<T: DeserializeOwned>(url: &str) -> T {
    serde_json::from_slice(&get_bytes(url).await).unwrap()
}

async fn assert_client_auth(
    email: &str,
    pass: &str,
    device_response: &DeviceAuthResponse,
    expect: &str,
) {
    let html_response = String::from_utf8_lossy(
        &post_bytes(
            &device_response.verification_uri,
            &AHashMap::from_iter([
                ("email".to_string(), email.to_string()),
                ("password".to_string(), pass.to_string()),
                ("code".to_string(), device_response.user_code.to_string()),
            ]),
        )
        .await,
    )
    .into_owned();
    assert!(html_response.contains(expect), "{:#?}", html_response);
}

async fn assert_unauthorized(base_url: &str, token: &str) {
    match Client::new()
        .credentials(Credentials::bearer(token))
        .accept_invalid_certs(true)
        .connect(base_url)
        .await
    {
        Ok(_) => panic!("Expected unauthorized access."),
        Err(err) => {
            let err = err.to_string();
            assert!(err.contains("Unauthorized"), "{}", err);
        }
    }
}

fn parse_code_input(bytes: Bytes) -> String {
    let html = String::from_utf8_lossy(&bytes).into_owned();
    if let Some((_, code)) = html.split_once("name=\"code\" value=\"") {
        if let Some((code, _)) = code.split_once('\"') {
            return code.to_string();
        }
    }
    panic!("Could not parse code input: {}", html);
}

fn parse_code_redirect(uri: String, state: &str) -> String {
    if let Some(code) = uri.strip_prefix("https://localhost?code=") {
        if let Some(code) = code.strip_suffix(&format!("&state={}", state)) {
            return code.to_string();
        }
    }
    panic!("Invalid redirect URI: {}", uri);
}

fn unwrap_token_response(response: TokenResponse) -> (String, Option<String>, u64) {
    match response {
        TokenResponse::Granted {
            access_token,
            token_type,
            expires_in,
            refresh_token,
            ..
        } => {
            assert_eq!(token_type, "bearer");
            (access_token, refresh_token, expires_in)
        }
        TokenResponse::Error { error } => panic!("Expected granted, got {:?}", error),
    }
}
