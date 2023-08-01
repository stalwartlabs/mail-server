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

use std::{collections::HashMap, fmt::Display, io::Read};

use jmap_client::{
    client::Client,
    principal::{
        query::{self},
        Property,
    },
};

pub mod cli;
pub mod database;
pub mod export;
pub mod import;
pub mod queue;
pub mod report;

const RETRY_ATTEMPTS: usize = 5;

pub trait UnwrapResult<T> {
    fn unwrap_result(self, action: &str) -> T;
}

impl<T> UnwrapResult<T> for Option<T> {
    fn unwrap_result(self, message: &str) -> T {
        match self {
            Some(result) => result,
            None => {
                eprintln!("Failed to {}", message);
                std::process::exit(1);
            }
        }
    }
}

impl<T, E: Display> UnwrapResult<T> for Result<T, E> {
    fn unwrap_result(self, message: &str) -> T {
        match self {
            Ok(result) => result,
            Err(err) => {
                eprintln!("Failed to {}: {}", message, err);
                std::process::exit(1);
            }
        }
    }
}

trait TableName {
    fn table_name(&self) -> &'static str;
}

impl TableName for Property {
    fn table_name(&self) -> &'static str {
        match self {
            Property::Id => "Id",
            Property::Type => "Type",
            Property::Name => "Name",
            Property::Description => "Description",
            Property::Email => "E-mail",
            Property::Timezone => "Timezone",
            Property::Capabilities => "Capabilities",
            Property::Aliases => "Aliases",
            Property::Secret => "Secret",
            Property::DKIM => "DKIM",
            Property::Quota => "Quota",
            Property::Picture => "Picture",
            Property::Members => "Members",
            Property::ACL => "ACL",
        }
    }
}

pub fn read_file(path: &str) -> Vec<u8> {
    if path == "-" {
        let mut stdin = std::io::stdin().lock();
        let mut raw_message = Vec::with_capacity(1024);
        let mut buf = [0; 1024];
        loop {
            let n = stdin.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            raw_message.extend_from_slice(&buf[..n]);
        }
        raw_message
    } else {
        std::fs::read(path).unwrap_or_else(|_| {
            eprintln!("Failed to read file: {}", path);
            std::process::exit(1);
        })
    }
}

pub async fn get(url: &str) -> HashMap<String, serde_json::Value> {
    serde_json::from_slice(
        &reqwest::Client::builder()
            .danger_accept_invalid_certs(is_localhost(url))
            .build()
            .unwrap_or_default()
            .get(url)
            .send()
            .await
            .unwrap_result("send OAuth GET request")
            .bytes()
            .await
            .unwrap_result("fetch bytes"),
    )
    .unwrap_result("deserialize OAuth GET response")
}

pub async fn post(
    url: &str,
    params: &HashMap<String, String>,
) -> HashMap<String, serde_json::Value> {
    serde_json::from_slice(
        &reqwest::Client::builder()
            .danger_accept_invalid_certs(is_localhost(url))
            .build()
            .unwrap_or_default()
            .post(url)
            .form(params)
            .send()
            .await
            .unwrap_result("send OAuth POST request")
            .bytes()
            .await
            .unwrap_result("fetch bytes"),
    )
    .unwrap_result("deserialize OAuth POST response")
}

pub async fn name_to_id(client: &Client, name: &str) -> String {
    let filter = if name.contains('@') {
        query::Filter::email(name)
    } else {
        query::Filter::name(name)
    };
    let mut response = client
        .principal_query(filter.into(), None::<Vec<_>>)
        .await
        .unwrap_result("query principals");
    match response.ids().len() {
        1 => response.take_ids().pop().unwrap(),
        0 => {
            eprintln!("Error: No principal found with name '{}'.", name);
            std::process::exit(1);
        }
        _ => {
            eprintln!("Error: Multiple principals found with name '{}'.", name);
            std::process::exit(1);
        }
    }
}

pub fn is_localhost(url: &str) -> bool {
    url.split_once("://")
        .map(|(_, url)| url.split_once('/').map_or(url, |(host, _)| host))
        .map_or(false, |host| {
            let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
            host == "localhost" || host == "127.0.0.1" || host == "[::1]"
        })
}

pub trait OAuthResponse {
    fn property(&self, name: &str) -> &str;
}

impl OAuthResponse for HashMap<String, serde_json::Value> {
    fn property(&self, name: &str) -> &str {
        self.get(name)
            .unwrap_result(&format!("find '{}' in OAuth response", name))
            .as_str()
            .unwrap_result(&format!("invalid '{}' value", name))
    }
}
