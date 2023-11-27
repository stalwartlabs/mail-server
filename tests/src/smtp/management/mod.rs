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

use std::time::Duration;

use reqwest::header::AUTHORIZATION;
use serde::{de::DeserializeOwned, Deserialize};

pub mod queue;
pub mod report;

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Response<T> {
    Data { data: T },
    Error { error: String, details: String },
}

pub async fn send_manage_request<T: DeserializeOwned>(query: &str) -> Result<Response<T>, String> {
    send_manage_request_raw(query).await.map(|result| {
        serde_json::from_str::<Response<T>>(&result).unwrap_or_else(|err| panic!("{err}: {result}"))
    })
}

pub async fn send_manage_request_raw(query: &str) -> Result<String, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:9980{query}"))
        .header(AUTHORIZATION, "Basic YWRtaW46c2VjcmV0")
        .send()
        .await
        .map_err(|err| err.to_string())?
        .bytes()
        .await
        .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
        .map_err(|err| err.to_string())
}

impl<T> Response<T> {
    pub fn unwrap_data(self) -> T {
        match self {
            Response::Data { data } => data,
            Response::Error { error, details } => {
                panic!("Expected data, found error {error:?}: {details:?}")
            }
        }
    }

    pub fn unwrap_error(self) -> (String, String) {
        match self {
            Response::Error { error, details } => (error, details),
            Response::Data { .. } => panic!("Expected error, found data."),
        }
    }
}
