/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::HashMap,
    fmt::Display,
    io::{BufRead, Write},
    time::Duration,
};

use clap::Parser;
use console::style;
use jmap_client::client::Credentials;
use modules::{
    cli::{Cli, Client, Commands},
    is_localhost, UnwrapResult,
};
use reqwest::{header::AUTHORIZATION, Method, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::modules::OAuthResponse;

pub mod modules;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Cli::parse();
    let url = args
        .url
        .or_else(|| std::env::var("URL").ok())
        .unwrap_or_else(|| {
            eprintln!("No URL specified. Use --url or set the URL environment variable.");
            std::process::exit(1);
        });
    let client = Client {
        credentials: if let Some(credentials) = args.credentials {
            parse_credentials(&credentials)
        } else if let Ok(credentials) = std::env::var("CREDENTIALS") {
            parse_credentials(&credentials)
        } else {
            let credentials = rpassword::prompt_password(
                "\nEnter administrator credentials or press [ENTER] to use OAuth: ",
            )
            .unwrap();
            if !credentials.is_empty() {
                parse_credentials(&credentials)
            } else {
                oauth(&url).await
            }
        },
        timeout: args.timeout,
        url,
    };

    match args.command {
        Commands::Import(command) => {
            command.exec(client).await;
        }
        Commands::Export(command) => {
            command.exec(client).await;
        }
        Commands::Server(command) => command.exec(client).await,
        Commands::Account(command) => command.exec(client).await,
        Commands::Domain(command) => command.exec(client).await,
        Commands::List(command) => command.exec(client).await,
        Commands::Group(command) => command.exec(client).await,
        Commands::Queue(command) => command.exec(client).await,
        Commands::Report(command) => command.exec(client).await,
    }

    Ok(())
}

fn parse_credentials(credentials: &str) -> Credentials {
    if let Some((account, secret)) = credentials.split_once(':') {
        Credentials::basic(account, secret)
    } else {
        Credentials::basic("admin", credentials)
    }
}

async fn oauth(url: &str) -> Credentials {
    let metadata: HashMap<String, serde_json::Value> = serde_json::from_slice(
        &reqwest::Client::builder()
            .danger_accept_invalid_certs(is_localhost(url))
            .build()
            .unwrap_or_default()
            .get(&format!("{}/.well-known/oauth-authorization-server", url))
            .send()
            .await
            .unwrap_result("send OAuth GET request")
            .bytes()
            .await
            .unwrap_result("fetch bytes"),
    )
    .unwrap_result("deserialize OAuth GET response");

    let token_endpoint = metadata.property("token_endpoint");
    let mut params: HashMap<String, String> =
        HashMap::from_iter([("client_id".to_string(), "Stalwart_CLI".to_string())]);
    let response: HashMap<String, serde_json::Value> = serde_json::from_slice(
        &reqwest::Client::builder()
            .danger_accept_invalid_certs(is_localhost(url))
            .build()
            .unwrap_or_default()
            .post(metadata.property("device_authorization_endpoint"))
            .form(&params)
            .send()
            .await
            .unwrap_result("send OAuth POST request")
            .bytes()
            .await
            .unwrap_result("fetch bytes"),
    )
    .unwrap_result("deserialize OAuth POST response");

    params.insert(
        "grant_type".to_string(),
        "urn:ietf:params:oauth:grant-type:device_code".to_string(),
    );
    params.insert(
        "device_code".to_string(),
        response.property("device_code").to_string(),
    );

    print!(
        "\nAuthenticate this request using code {} at {}. Please ENTER when done.",
        style(response.property("user_code")).bold(),
        style(response.property("verification_uri")).bold().dim()
    );

    std::io::stdout().flush().unwrap();
    std::io::stdin().lock().lines().next();

    let mut response: HashMap<String, serde_json::Value> = serde_json::from_slice(
        &reqwest::Client::builder()
            .danger_accept_invalid_certs(is_localhost(url))
            .build()
            .unwrap_or_default()
            .post(token_endpoint)
            .form(&params)
            .send()
            .await
            .unwrap_result("send OAuth POST request")
            .bytes()
            .await
            .unwrap_result("fetch bytes"),
    )
    .unwrap_result("deserialize OAuth POST response");

    if let Some(serde_json::Value::String(access_token)) = response.remove("access_token") {
        Credentials::Bearer(access_token)
    } else {
        eprintln!(
            "OAuth failed with code {}.",
            response
                .get("error")
                .and_then(|s| s.as_str())
                .unwrap_or("<unknown>")
        );
        std::process::exit(1);
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Response<T> {
    Error(ManagementApiError),
    Data { data: T },
}

#[derive(Deserialize)]
#[serde(tag = "error")]
pub enum ManagementApiError {
    FieldAlreadyExists { field: String, value: String },
    FieldMissing { field: String },
    NotFound { item: String },
    Unsupported { details: String },
    AssertFailed,
    Other { details: String },
    UnsupportedDirectoryOperation { class: String },
}

impl Client {
    pub async fn into_jmap_client(self) -> jmap_client::client::Client {
        jmap_client::client::Client::new()
            .credentials(self.credentials)
            .accept_invalid_certs(is_localhost(&self.url))
            .timeout(Duration::from_secs(self.timeout.unwrap_or(60)))
            .connect(&self.url)
            .await
            .unwrap_or_else(|err| {
                eprintln!("Failed to connect to JMAP server {}: {}.", &self.url, err);
                std::process::exit(1);
            })
    }

    pub async fn http_request<R: DeserializeOwned, B: Serialize>(
        &self,
        method: Method,
        url: &str,
        body: Option<B>,
    ) -> R {
        self.try_http_request(method, url, body)
            .await
            .unwrap_or_else(|| {
                eprintln!("Request failed: No data returned.");
                std::process::exit(1);
            })
    }

    pub async fn try_http_request<R: DeserializeOwned, B: Serialize>(
        &self,
        method: Method,
        url: &str,
        body: Option<B>,
    ) -> Option<R> {
        let url = format!(
            "{}{}{}",
            self.url,
            if !self.url.ends_with('/') && !url.starts_with('/') {
                "/"
            } else {
                ""
            },
            url
        );
        let mut request = reqwest::Client::builder()
            .danger_accept_invalid_certs(is_localhost(&url))
            .timeout(Duration::from_secs(self.timeout.unwrap_or(60)))
            .build()
            .unwrap_or_default()
            .request(method, url)
            .header(
                AUTHORIZATION,
                match &self.credentials {
                    Credentials::Basic(s) => format!("Basic {s}"),
                    Credentials::Bearer(s) => format!("Bearer {s}"),
                },
            );

        if let Some(body) = body {
            request = request.body(serde_json::to_string(&body).unwrap_result("serialize body"));
        }

        let response = request.send().await.unwrap_result("send HTTP request");

        match response.status() {
            StatusCode::OK => (),
            StatusCode::NOT_FOUND => {
                return None;
            }
            StatusCode::UNAUTHORIZED => {
                eprintln!("Authentication failed. Make sure the credentials are correct and that the account has administrator rights.");
                std::process::exit(1);
            }
            _ => {
                eprintln!(
                    "Request failed: {}",
                    response.text().await.unwrap_result("fetch text")
                );
                std::process::exit(1);
            }
        }

        let bytes = response.bytes().await.unwrap_result("fetch bytes");
        match serde_json::from_slice::<Response<R>>(&bytes).unwrap_result(&format!(
            "deserialize response {}",
            String::from_utf8_lossy(bytes.as_ref())
        )) {
            Response::Data { data } => Some(data),
            Response::Error(error) => {
                eprintln!("Request failed: {error})");
                std::process::exit(1);
            }
        }
    }
}

impl Display for ManagementApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagementApiError::FieldAlreadyExists { field, value } => {
                write!(f, "Field {} already exists with value {}.", field, value)
            }
            ManagementApiError::FieldMissing { field } => {
                write!(f, "Field {} is missing.", field)
            }
            ManagementApiError::NotFound { item } => {
                write!(f, "{} not found.", item)
            }
            ManagementApiError::Unsupported { details } => {
                write!(f, "Unsupported: {}", details)
            }
            ManagementApiError::AssertFailed => {
                write!(f, "Assertion failed.")
            }
            ManagementApiError::Other { details } => {
                write!(f, "{}", details)
            }
            ManagementApiError::UnsupportedDirectoryOperation { class } => {
                write!(f, "This operation is only available on internal directories. Your current directory is {class}.")
            }
        }
    }
}
