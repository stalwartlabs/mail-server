/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use bytes::Bytes;
use directory::backend::internal::manage::ManageDirectory;
use jmap::auth::oauth::{
    DeviceAuthResponse, ErrorType, OAuthCodeRequest, OAuthMetadata, TokenResponse,
};
use jmap_client::{
    client::{Client, Credentials},
    mailbox::query::Filter,
};
use jmap_proto::types::id::Id;
use serde::de::DeserializeOwned;
use store::ahash::AHashMap;

use crate::jmap::{assert_is_empty, mailbox::destroy_all_mailboxes, ManagementApi};

use super::JMAPTest;

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct OAuthCodeResponse {
    code: String,
    is_admin: bool,
    is_enterprise: bool,
}

pub async fn test(params: &mut JMAPTest) {
    println!("Running OAuth tests...");

    // Create test account
    let server = params.server.clone();
    params
        .directory
        .create_test_user_with_email("jdoe@example.com", "12345", "John Doe")
        .await;
    let john_id = Id::from(
        server
            .core
            .storage
            .data
            .get_or_create_account_id("jdoe@example.com")
            .await
            .unwrap(),
    )
    .to_string();

    // Build API
    let api = ManagementApi::new(8899, "jdoe@example.com", "12345");

    // Obtain OAuth metadata
    let metadata: OAuthMetadata =
        get("https://127.0.0.1:8899/.well-known/oauth-authorization-server").await;
    //println!("OAuth metadata: {:#?}", metadata);

    // ------------------------
    // Authorization code flow
    // ------------------------

    // Authenticate with the correct password
    let response = api
        .post::<OAuthCodeResponse>(
            "/api/oauth",
            &OAuthCodeRequest::Code {
                client_id: "OAuthyMcOAuthFace".to_string(),
                redirect_uri: "https://localhost".to_string().into(),
            },
        )
        .await
        .unwrap()
        .unwrap_data();

    // Both client_id and redirect_uri have to match
    let mut token_params = AHashMap::from_iter([
        ("client_id".to_string(), "invalid_client".to_string()),
        ("redirect_uri".to_string(), "https://localhost".to_string()),
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), response.code),
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

    // Let the code expire and make sure it's invalidated
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !api.post::<bool>(
            "/api/oauth",
            &OAuthCodeRequest::Device {
                code: device_response.user_code.clone(),
            },
        )
        .await
        .unwrap()
        .unwrap_data(),
        "Code should be expired"
    );
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
    assert!(
        api.post::<bool>(
            "/api/oauth",
            &OAuthCodeRequest::Device {
                code: device_response.user_code.clone(),
            },
        )
        .await
        .unwrap()
        .unwrap_data(),
        "Code is invalid"
    );

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
    server
        .core
        .storage
        .lookup
        .purge_lookup_store()
        .await
        .unwrap();
    params.client.set_default_account_id(john_id);
    destroy_all_mailboxes(params).await;
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

fn unwrap_token_response(response: TokenResponse) -> (String, Option<String>, u64) {
    match response {
        TokenResponse::Granted(granted) => {
            assert_eq!(granted.token_type, "bearer");
            (
                granted.access_token,
                granted.refresh_token,
                granted.expires_in,
            )
        }
        TokenResponse::Error { error } => panic!("Expected granted, got {:?}", error),
    }
}
