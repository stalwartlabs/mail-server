/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
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
    collections::HashMap,
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
    Data { data: T },
    Error { error: String, details: String },
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

        match serde_json::from_slice::<Response<R>>(
            &response.bytes().await.unwrap_result("fetch bytes"),
        )
        .unwrap_result("deserialize response")
        {
            Response::Data { data } => data,
            Response::Error { error, details } => {
                eprintln!("Request failed: {details} ({error:?})");
                std::process::exit(1);
            }
        }
    }
}
