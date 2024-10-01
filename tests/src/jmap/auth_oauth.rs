/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use base64::{engine::general_purpose, Engine};
use biscuit::{jwk::JWKSet, SingleOrMultiple, JWT};
use bytes::Bytes;
use common::auth::oauth::{
    introspect::OAuthIntrospect,
    registration::{ClientRegistrationRequest, ClientRegistrationResponse},
};
use imap_proto::ResponseType;
use jmap::auth::oauth::{
    auth::OAuthMetadata, openid::OpenIdMetadata, DeviceAuthResponse, ErrorType, OAuthCodeRequest,
    TokenResponse,
};
use jmap_client::{
    client::{Client, Credentials},
    mailbox::query::Filter,
};
use jmap_proto::types::id::Id;
use serde::{de::DeserializeOwned, Serialize};
use store::ahash::AHashMap;

use crate::{
    directory::internal::TestInternalDirectory,
    imap::{
        pop::{self, Pop3Connection},
        ImapConnection, Type,
    },
    jmap::{
        assert_is_empty, delivery::SmtpConnection, mailbox::destroy_all_mailboxes, ManagementApi,
    },
};

use super::JMAPTest;

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct OAuthCodeResponse {
    pub code: String,
    #[serde(rename = "isEnterprise")]
    pub is_enterprise: bool,
}

pub async fn test(params: &mut JMAPTest) {
    println!("Running OAuth tests...");

    // Create test account
    let server = params.server.clone();
    let john_int_id = server
        .core
        .storage
        .data
        .create_test_user(
            "jdoe@example.com",
            "12345",
            "John Doe",
            &["jdoe@example.com"],
        )
        .await;
    let john_id = Id::from(john_int_id).to_string();

    // Build API
    let api = ManagementApi::new(8899, "jdoe@example.com", "12345");

    // Obtain OAuth metadata
    let metadata: OAuthMetadata =
        get("https://127.0.0.1:8899/.well-known/oauth-authorization-server").await;
    let oidc_metadata: OpenIdMetadata =
        get("https://127.0.0.1:8899/.well-known/openid-configuration").await;
    let jwk_set: JWKSet<()> = get(&oidc_metadata.jwks_uri).await;

    // Register client
    let registration: ClientRegistrationResponse = post_json(
        &metadata.registration_endpoint,
        None,
        &ClientRegistrationRequest {
            redirect_uris: vec!["https://localhost".to_string()],
            ..Default::default()
        },
    )
    .await;
    let client_id = registration.client_id;

    /*println!("OAuth metadata: {:#?}", metadata);
    println!("OpenID metadata: {:#?}", oidc_metadata);
    println!("JWKSet: {:#?}", jwk_set);*/

    // ------------------------
    // Authorization code flow
    // ------------------------

    // Authenticate with the correct password
    let response = api
        .post::<OAuthCodeResponse>(
            "/api/oauth",
            &OAuthCodeRequest::Code {
                client_id: client_id.to_string(),
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
    token_params.insert("client_id".to_string(), client_id.to_string());
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
    let (token, refresh_token, id_token) =
        unwrap_oidc_token_response(post(&metadata.token_endpoint, &token_params).await);

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

    // Verify ID token using the JWK set
    let id_token = JWT::<(), biscuit::Empty>::new_encoded(&id_token)
        .decode_with_jwks(&jwk_set, None)
        .unwrap();
    let claims = &id_token.payload().unwrap().registered;
    assert_eq!(claims.issuer, Some(oidc_metadata.issuer));
    assert_eq!(claims.subject, Some(john_int_id.to_string()));
    assert_eq!(
        claims.audience,
        Some(SingleOrMultiple::Single(client_id.to_string()))
    );

    // Introspect token
    let access_introspect: OAuthIntrospect = post_with_auth::<OAuthIntrospect>(
        &metadata.introspection_endpoint,
        token.as_str().into(),
        &AHashMap::from_iter([("token".to_string(), token.to_string())]),
    )
    .await;
    assert_eq!(access_introspect.username.unwrap(), "jdoe@example.com");
    assert_eq!(access_introspect.token_type.unwrap(), "bearer");
    assert_eq!(access_introspect.client_id.unwrap(), client_id);
    assert!(access_introspect.active);
    let refresh_introspect = post_with_auth::<OAuthIntrospect>(
        &metadata.introspection_endpoint,
        token.as_str().into(),
        &AHashMap::from_iter([("token".to_string(), refresh_token.unwrap())]),
    )
    .await;
    assert_eq!(refresh_introspect.username.unwrap(), "jdoe@example.com");
    assert_eq!(refresh_introspect.client_id.unwrap(), client_id);
    assert!(refresh_introspect.active);
    assert_eq!(
        refresh_introspect.iat.unwrap(),
        access_introspect.iat.unwrap()
    );

    // Try SMTP OAUTHBEARER auth
    let oauth_bearer_invalid_sasl = general_purpose::STANDARD.encode(format!(
        "n,a={},\u{1}auth=Bearer {}\u{1}\u{1}",
        "user@domain", "invalid_token"
    ));
    let oauth_bearer_sasl = general_purpose::STANDARD.encode(format!(
        "n,a={},\u{1}auth=Bearer {}\u{1}\u{1}",
        "user@domain", token
    ));
    let mut smtp = SmtpConnection::connect().await;
    smtp.send(&format!("AUTH OAUTHBEARER {oauth_bearer_invalid_sasl}",))
        .await;
    smtp.read(1, 4).await;
    smtp.send(&format!("AUTH OAUTHBEARER {oauth_bearer_sasl}",))
        .await;
    smtp.read(1, 2).await;

    // Try IMAP OAUTHBEARER auth
    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.assert_read(Type::Untagged, ResponseType::Ok).await;
    imap.send(&format!("AUTHENTICATE OAUTHBEARER {oauth_bearer_sasl}"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Try POP3 OAUTHBEARER auth
    let mut pop3 = Pop3Connection::connect().await;
    pop3.assert_read(pop::ResponseType::Ok).await;
    pop3.send(&format!("AUTH OAUTHBEARER {oauth_bearer_sasl}"))
        .await;
    pop3.assert_read(pop::ResponseType::Ok).await;

    // ------------------------
    // Device code flow
    // ------------------------

    // Request a device code
    let device_code_params =
        AHashMap::from_iter([("client_id".to_string(), client_id.to_string())]);
    let device_response: DeviceAuthResponse =
        post(&metadata.device_authorization_endpoint, &device_code_params).await;
    //println!("Device response: {:#?}", device_response);

    // Status should be pending
    let mut token_params = AHashMap::from_iter([
        ("client_id".to_string(), client_id.to_string()),
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
                ("client_id".to_string(), client_id.to_string()),
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
        ("client_id".to_string(), client_id.to_string()),
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

async fn post_bytes(
    url: &str,
    auth_token: Option<&str>,
    params: &AHashMap<String, String>,
) -> Bytes {
    let mut client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .post(url);

    if let Some(auth_token) = auth_token {
        client = client.bearer_auth(auth_token);
    }

    client
        .form(params)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
}

async fn post_json<D: DeserializeOwned>(
    url: &str,
    auth_token: Option<&str>,
    body: &impl Serialize,
) -> D {
    let mut client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .post(url);

    if let Some(auth_token) = auth_token {
        client = client.bearer_auth(auth_token);
    }

    serde_json::from_slice(
        &client
            .body(serde_json::to_string(body).unwrap().into_bytes())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn post<T: DeserializeOwned>(url: &str, params: &AHashMap<String, String>) -> T {
    post_with_auth(url, None, params).await
}
async fn post_with_auth<T: DeserializeOwned>(
    url: &str,
    auth_token: Option<&str>,
    params: &AHashMap<String, String>,
) -> T {
    serde_json::from_slice(&post_bytes(url, auth_token, params).await).unwrap()
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

fn unwrap_oidc_token_response(response: TokenResponse) -> (String, Option<String>, String) {
    match response {
        TokenResponse::Granted(granted) => {
            assert_eq!(granted.token_type, "bearer");
            (
                granted.access_token,
                granted.refresh_token,
                granted.id_token.unwrap(),
            )
        }
        TokenResponse::Error { error } => panic!("Expected granted, got {:?}", error),
    }
}
